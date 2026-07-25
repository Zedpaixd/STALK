#include "tracker.h"
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <bpf/bpf.h>

static constexpr double WATCH_THRESHOLD = 0.40;
static constexpr std::size_t WATCH_MAX = 20;
static constexpr std::size_t MASQ_CAP = 100;

#define TLOG(...) do { std::fprintf(stderr, "[T] " __VA_ARGS__); std::fprintf(stderr, "\n"); } while (0)

enum PromptAct { PA_NONE = 0, PA_RESUME, PA_FREEZE, PA_KILL, PA_WHITELIST };

static const struct { const char *name; const char *desc; } PROMPT_ACTIONS[] = {
    { "none",      "take no action; leave the process as-is" },
    { "resume",    "resume execution (SIGCONT)" },
    { "freeze",    "keep suspended, blocking further activity (SIGSTOP)" },
    { "kill",      "terminate the process group (SIGKILL)" },
    { "whitelist", "allow for this session; resume & stop scoring" },
};

static int act_index(const std::string &s) {
    int n = (int)(sizeof(PROMPT_ACTIONS) / sizeof(PROMPT_ACTIONS[0]));
    for (int i = 0; i < n; i++) if (s == PROMPT_ACTIONS[i].name) return i;
    return PA_NONE;
}
static const char *act_desc(const std::string &s) { return PROMPT_ACTIONS[act_index(s)].desc; }

static std::string ev_action_desc(std::uint8_t t) {
    switch (t) {
        case EV_EXEC: return "execute a new binary (execve)";
        case EV_MEMFD_CREATE: return "create an in-memory file (memfd_create; fileless exec)";
        case EV_MPROTECT_WX: return "make memory writable+executable (mprotect W^X; injection)";
        case EV_PTRACE: return "attach to another process (ptrace; memory tampering)";
        case EV_COMMIT_CREDS: return "escalate privileges to root (commit_creds)";
        case EV_UNSHARE: return "create a new namespace (unshare; isolation/escape)";
        case EV_PRCTL_RENAME: return "disguise its process name (prctl PR_SET_NAME)";
        case EV_SEC_BPF: return "load an eBPF program (bpf syscall)";
        case EV_TCP_CONNECT: return "open an outbound connection (possible C2)";
    }
    return "perform a suspicious operation";
}

static const char *evname(std::uint8_t t) {
    switch (t) {
        case EV_FORK: return "FORK";
        case EV_EXIT: return "EXIT";
        case EV_EXEC: return "EXEC";
        case EV_MPROTECT_WX: return "WX";
        case EV_MEMFD_CREATE: return "MEMFD";
        case EV_PRCTL_RENAME: return "RENAME";
        case EV_PTRACE: return "PTRACE";
        case EV_COMMIT_CREDS: return "CREDS";
        case EV_UNSHARE: return "UNSHARE";
        case EV_SEC_BPF: return "SECBPF";
        case EV_TCP_CONNECT: return "CONNECT";
        case EV_LSM_DENY: return "LSMDENY";
        case EV_BURST_TRIP: return "BURST";
    }
    return "?";
}

void Tracker::inherit_identity(std::uint32_t child_tgid, std::uint32_t parent_tgid) {
    if (child_tgid == 0 || parent_tgid == 0 || child_tgid == parent_tgid) return;
    auto fit = tgid_fid_.find(parent_tgid);
    if (fit == tgid_fid_.end() || !fit->second.valid()) return;
    tgid_fid_[child_tgid] = fit->second;
    auto pit = tgid_path_.find(parent_tgid);
    if (pit != tgid_path_.end()) tgid_path_[child_tgid] = pit->second;
    auto hit = tgid_hash_.find(parent_tgid);
    if (hit != tgid_hash_.end()) tgid_hash_[child_tgid] = hit->second;
    TLOG("INHERIT child=%u <- parent=%u fid=%s hash=%d",
         child_tgid, parent_tgid, fit->second.key().c_str(),
         (int)(tgid_hash_.find(child_tgid) != tgid_hash_.end()));
}

void Tracker::prime_identity(const edr_event &e) {
    if (!hasher_) return;
    FileId id;
    id.ino       = e.data.exec.fid.ino;
    id.size      = e.data.exec.fid.size;
    id.mtime_ns  = e.data.exec.fid.mtime_ns;
    id.dev_major = e.data.exec.fid.dev_major;
    id.dev_minor = e.data.exec.fid.dev_minor;
    if (!id.valid()) return;
    std::string kpath(e.data.exec.filename, ::strnlen(e.data.exec.filename, MAX_PATH_LEN));
    std::string cached;
    bool have = hasher_->lookup(id, cached);
    std::string path;
    int fd = BinHasher::open_verified(e.tgid, id, path);
    const char *via = "proc";
    if (fd < 0 && !kpath.empty()) {
        fd = BinHasher::open_path_verified(kpath, id);
        if (fd >= 0) { path = kpath; via = "path"; }
    }
    if (fd >= 0) {
        if (have) ::close(fd);
        else hasher_->submit(fd, id, path);
    }
    std::unique_lock<std::shared_mutex> lk(g_lock_);
    tgid_fid_[e.tgid] = id;
    if (!path.empty()) tgid_path_[e.tgid] = path;
    if (!cached.empty()) tgid_hash_[e.tgid] = cached;
    TLOG("PRIME tgid=%u fid=%s fd=%d via=%s cached=%d path='%s'",
         e.tgid, id.key().c_str(), fd, via, (int)have,
         path.empty() ? "(none)" : path.c_str());
}

void Tracker::on_hash_ready(const FileId &id, const std::string &hash, const std::string &path) {
    std::vector<std::uint32_t> hits;
    {
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        for (auto &kv : tgid_fid_) {
            if (kv.second.key() != id.key()) continue;
            hits.push_back(kv.first);
            tgid_hash_[kv.first] = hash;
            if (!path.empty()) tgid_path_[kv.first] = path;
            auto n = lookup_by_pid(kv.first);
            if (n) {
                n->cached_hash = hash;
                if (!path.empty() && n->cached_path.empty()) n->cached_path = path;
            }
        }
    }
    if (!rep_) return;
    if (rep_->is_whitelisted(hash)) {
        for (auto tg : hits) {
            std::unique_lock<std::shared_mutex> lk(g_lock_);
            auto n = lookup_by_pid(tg);
            if (n && !n->is_dead) { n->exempt = true; n->blocked = false; kernel_exempt(tg, true); }
        }
        return;
    }
    if (rep_->is_blacklisted(hash)) reblock_from_reputation(hash);
}

static double now_sec() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}
static double ns_to_sec(std::uint64_t ns) { return static_cast<double>(ns) / 1e9; }

static std::string now_hms_ms() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::tm tmv;
    localtime_r(&t, &tmv);
    char b[16];
    std::snprintf(b, sizeof(b), "%02d:%02d:%02d.%03d",
        tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (int)ms.count());
    return b;
}

static int ev_category(std::uint8_t t) {
    switch (t) {
        case EV_FORK: case EV_EXIT: return CAT_LIFECYCLE;
        case EV_EXEC: case EV_MEMFD_CREATE: return CAT_EXECUTION;
        case EV_MPROTECT_WX: case EV_PTRACE: return CAT_MEMORY;
        case EV_COMMIT_CREDS: case EV_UNSHARE: return CAT_PRIVILEGE;
        case EV_PRCTL_RENAME: case EV_SEC_BPF: return CAT_EVASION;
        case EV_TCP_CONNECT: return CAT_C2;
    }
    return CAT_LIFECYCLE;
}

Tracker::Tracker(EngineCfg cfg, std::uint32_t own_pgid, std::uint32_t own_pid,
                 std::shared_ptr<Reputation> rep)
    : cfg_(std::move(cfg)), own_pgid_(own_pgid), own_pid_(own_pid), rep_(std::move(rep)) {
    start_ts_ = now_sec();
    last_epoch_bump_ = start_ts_;
    if (cfg_.exempt_comms.empty()) {
        cfg_.exempt_comms = { "bash", "sh", "dash", "zsh", "fish", "ksh", "ash",
                              "python", "python3", "perl", "ruby", "node", "env",
                              "sudo", "su", "login", "systemd", "init",
                              "init(kali-linux", "SessionLeader", "Relay" };
    }
    TLOG("CTOR own_pid=%u own_pgid=%u prompt_enabled=%d prompt_thr=%.2f prompt_floor=%.2f warmup=%.1f",
         own_pid_, own_pgid_, (int)cfg_.prompt_enabled, cfg_.prompt_threshold,
         cfg_.prompt_event_floor, cfg_.warmup_sec);
}

double Tracker::warmup_remaining() const {
    double r = cfg_.warmup_sec - (now_sec() - start_ts_);
    return r > 0.0 ? r : 0.0;
}

std::string Tracker::mk_uid(std::uint32_t tgid, std::uint64_t ts_ns) const {
    return std::to_string(tgid) + "_" + std::to_string(ts_ns);
}

std::string Tracker::ev_key(std::uint8_t t) const {
    switch (t) {
        case EV_FORK: return "ev_fork";
        case EV_EXIT: return "ev_exit";
        case EV_EXEC: return "ev_exec";
        case EV_MPROTECT_WX: return "ev_mprotect_wx";
        case EV_MEMFD_CREATE: return "ev_memfd_create";
        case EV_PRCTL_RENAME: return "ev_prctl_rename";
        case EV_PTRACE: return "ev_ptrace";
        case EV_COMMIT_CREDS: return "ev_commit_creds";
        case EV_UNSHARE: return "ev_unshare";
        case EV_SEC_BPF: return "ev_sec_bpf";
        case EV_TCP_CONNECT: return "ev_tcp_connect";
    }
    return "ev_unknown";
}

bool Tracker::self_pid(std::uint32_t pid, std::uint32_t pgid) const {
    if (pid == own_pid_ || pgid == own_pgid_) return true;
    if (pid == 0) return false;
    std::uint32_t c = pid;
    for (int i = 0; i < 16 && c > 1; i++) {
        if (c == own_pid_) return true;
        char sp[64];
        std::snprintf(sp, sizeof(sp), "/proc/%u/stat", c);
        int fd = ::open(sp, O_RDONLY);
        if (fd < 0) break;
        char b[256];
        ssize_t bn = ::read(fd, b, sizeof(b) - 1);
        ::close(fd);
        if (bn <= 0) break;
        b[bn] = 0;
        char *rr = std::strrchr(b, ')');
        if (!rr) break;
        char st; unsigned pp = 0;
        if (std::sscanf(rr + 1, " %c %u", &st, &pp) != 2) break;
        if (pp == own_pid_) return true;
        c = pp;
    }
    return false;
}
bool Tracker::is_self(const edr_event &e) const {
    return e.tgid == own_pid_ || self_pid(e.pid, e.pgid);
}
bool Tracker::is_exempt_comm(const char *nm) const {
    if (!nm || !nm[0]) return false;
    for (auto &pat : cfg_.exempt_comms)
        if (std::strncmp(nm, pat.c_str(), MAX_COMM) == 0) return true;
    return false;
}
bool Tracker::is_masq_name(const char *nm) const {
    if (!nm || !nm[0]) return false;
    for (auto &pat : cfg_.masq_names)
        if (std::strncmp(nm, pat.c_str(), pat.size()) == 0) return true;
    return false;
}

bool Tracker::node_is_supervised(const std::shared_ptr<ProcNode> &n) const {
    auto cur = n;
    int guard = 0;
    int hops = 0;
    while (cur && guard++ < 256) {
        if (cur->supervised) return true;
        if (supervised_roots_.count(cur->tgid)) return true;
        cur = cur->parent.lock();
        hops++;
    }
    if (n && std::strncmp(n->comm, "edr", 3) == 0)
        TLOG("SUPCHK tgid=%u comm='%.16s' -> NOT supervised (walked %d hops, roots=%zu)",
             n->tgid, n->comm, hops, supervised_roots_.size());
    return false;
}

void Tracker::kernel_exempt(std::uint32_t tgid, bool on) {
    if (exempt_fd_ < 0 || tgid == 0) return;
    if (on) {
        std::uint8_t v = 1;
        bpf_map_update_elem(exempt_fd_, &tgid, &v, BPF_ANY);
    } else {
        bpf_map_delete_elem(exempt_fd_, &tgid);
    }
}

void Tracker::remember_exec(std::uint32_t tgid, const std::string &path, const std::string &hash) {
    if (tgid == 0) return;
    static constexpr std::size_t REMEMBER_CAP = 8192;
    if (!path.empty()) {
        if (tgid_path_.size() >= REMEMBER_CAP && tgid_path_.find(tgid) == tgid_path_.end())
            tgid_path_.clear();
        tgid_path_[tgid] = path;
    }
    if (!hash.empty()) {
        if (tgid_hash_.size() >= REMEMBER_CAP && tgid_hash_.find(tgid) == tgid_hash_.end())
            tgid_hash_.clear();
        tgid_hash_[tgid] = hash;
    }
    TLOG("REMEMBER tgid=%u path='%s' hash=%s",
         tgid, path.empty() ? "(none)" : path.c_str(), hash.empty() ? "(none)" : "ok");
}

void Tracker::log_alert(const std::string &s) {
    std::lock_guard<std::mutex> lk(alert_lock_);
    alerts_.push_back("[" + now_hms_ms() + "] " + s);
    if (alerts_.size() > 200) alerts_.pop_front();
}

void Tracker::register_supervised(std::uint32_t tgid) {
    if (tgid == 0) return;
    std::unique_lock<std::shared_mutex> lk(g_lock_);
    supervised_roots_.insert(tgid);
    kernel_exempt(tgid, true);
    auto n = lookup_by_pid(tgid);
    if (n) { n->supervised = true; n->exempt = false; }
    TLOG("REG-SUP tgid=%u node_found=%d roots_now=%zu", tgid, (int)(bool)n, supervised_roots_.size());
    char m[128];
    std::snprintf(m, sizeof(m), "[SECCOMP] now supervising pid=%u (eBPF muted for its tree; scoring only)", tgid);
    log_alert(m);
}

void Tracker::unregister_supervised(std::uint32_t tgid) {
    if (tgid == 0) return;
    std::unique_lock<std::shared_mutex> lk(g_lock_);
    supervised_roots_.erase(tgid);
    TLOG("UNREG-SUP tgid=%u roots_now=%zu", tgid, supervised_roots_.size());
    char m[96];
    std::snprintf(m, sizeof(m), "[SECCOMP] supervision ended for pid=%u", tgid);
    log_alert(m);
}

int Tracker::syscall_to_evtype(int nr, std::uint64_t a0, std::uint64_t a2) const {
#ifdef __NR_memfd_create
    if (nr == __NR_memfd_create) return EV_MEMFD_CREATE;
#endif
#ifdef __NR_mprotect
    if (nr == __NR_mprotect) {
        bool wx = (a2 & 0x2) && (a2 & 0x4);
        return wx ? EV_MPROTECT_WX : -1;
    }
#endif
#ifdef __NR_ptrace
    if (nr == __NR_ptrace) return EV_PTRACE;
#endif
#ifdef __NR_unshare
    if (nr == __NR_unshare) return EV_UNSHARE;
#endif
#ifdef __NR_connect
    if (nr == __NR_connect) return EV_TCP_CONNECT;
#endif
#ifdef __NR_execveat
    if (nr == __NR_execveat) return EV_EXEC;
#endif
#ifdef __NR_prctl
    if (nr == __NR_prctl) {
        if (a0 == 15) return EV_PRCTL_RENAME;
        return -1;
    }
#endif
    return -1;
}

RiskPrediction Tracker::predict_for_syscall(std::uint32_t tgid, int syscall_nr,
                                            std::uint64_t a0, std::uint64_t a1, std::uint64_t a2) {
    (void)a1;
    RiskPrediction rp;
    if (rep_) rp.exe_path = rep_->resolve_exe(tgid);

    std::unique_lock<std::shared_mutex> lk(g_lock_);
    auto n = lookup_by_pid(tgid);
    if (!n) {
        bool sup = supervised_roots_.count(tgid) > 0;
        TLOG("PREDICT tgid=%u no node -> synth(sup=%d)", tgid, (int)sup);
        n = synth_node(tgid, sup);
        if (n) {
            char m[128];
            std::snprintf(m, sizeof(m),
                "[SECCOMP] pid=%u %s added to eBPF model (synthesised from /proc)",
                tgid, n->comm);
            log_alert(m);
        }
    }
    if (!n) {
        TLOG("PREDICT tgid=%u UNKNOWN (synth failed)", tgid);
        rp.known = false;
        return rp;
    }

    int evtype = syscall_to_evtype(syscall_nr, a0, a2);
    std::string k = (evtype >= 0) ? ev_key((std::uint8_t)evtype) : std::string();
    double base = (evtype >= 0) ? MathEng::llr_for(cfg_, k) : 0.0;
    int cat = (evtype >= 0) ? ev_category((std::uint8_t)evtype) : -1;
    bool scores = (evtype >= 0 && base > 0.0);

    TLOG("PREDICT tgid=%u comm='%.16s' nr=%d evtype=%d base=%.2f scores=%d sup=%d exempt=%d",
         tgid, n->comm, syscall_nr, evtype, base, (int)scores,
         (int)node_is_supervised(n), (int)n->exempt);

    auto predict_node = [&](const std::shared_ptr<ProcNode> &node) -> double {
        double sim[CAT_COUNT];
        double t = now_sec();
        double dt = t - node->last_score_ts;
        for (int c = 0; c < CAT_COUNT; c++) {
            sim[c] = node->cat_accum[c];
            if (dt > 0.0)
                sim[c] = MathEng::decay_accum(sim[c], dt, cfg_.cats[c].half_life);
        }
        if (scores && cat >= 0) {
            double mult = 1.0;
            if (node->owner_uid == 0) mult *= cfg_.ctx_uid0;
            sim[cat] += base * mult;
        }
        double S = cfg_.prior_logodds;
        if (!node->is_new) S += cfg_.seeded_prior_extra;
        int na = 0;
        for (int c = 0; c < CAT_COUNT; c++) {
            double contrib = MathEng::cat_contrib(sim[c], cfg_.cats[c].max_llr, cfg_.cats[c].scale);
            S += contrib;
            if (contrib >= cfg_.active_floor) na++;
        }
        if (na >= 2) S += cfg_.corrob_coeff * (na - 1);
        return MathEng::sigmoid_stable(S);
    };

    rp.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
    rp.current = n->risk_pct;
    rp.known = true;
    rp.scores = scores;
    rp.predicted = scores ? predict_node(n) : rp.current;

    std::shared_ptr<ProcNode> sup_root;
    {
        auto cur = n;
        int guard = 0;
        while (cur && guard++ < 256) {
            if (supervised_roots_.count(cur->tgid)) { sup_root = cur; break; }
            cur = cur->parent.lock();
        }
        if (!sup_root) {
            std::uint32_t c = tgid;
            for (int g2 = 0; g2 < 64 && c > 1; g2++) {
                if (supervised_roots_.count(c)) {
                    sup_root = lookup_by_pid(c);
                    if (!sup_root) sup_root = synth_node(c, true);
                    break;
                }
                char sp[64];
                std::snprintf(sp, sizeof(sp), "/proc/%u/stat", c);
                int fd = ::open(sp, O_RDONLY);
                if (fd < 0) break;
                char b[256];
                ssize_t bn = ::read(fd, b, sizeof(b) - 1);
                ::close(fd);
                if (bn <= 0) break;
                b[bn] = 0;
                char *rr = std::strrchr(b, ')');
                if (!rr) break;
                char st; unsigned pp = 0;
                if (std::sscanf(rr + 1, " %c %u", &st, &pp) != 2) break;
                c = pp;
            }
        }
    }
    if (sup_root) {
        std::shared_ptr<ProcNode> best;
        for (auto &kv : nodes_) {
            auto &m = kv.second;
            if (!m || m->exempt || m->is_dead) continue;
            if (!node_is_supervised(m)) continue;
            if (!best || m->risk_pct > best->risk_pct) best = m;
        }
        if (best && best.get() != n.get()) {
            rp.has_parent = true;
            rp.parent_comm.assign(best->comm, ::strnlen(best->comm, MAX_COMM));
            rp.parent_current = best->risk_pct;
            rp.parent_predicted = best->risk_pct;
        }
    }
    return rp;
}

void Tracker::commit_syscall_evidence(std::uint32_t tgid, int syscall_nr,
                                      std::uint64_t a0, std::uint64_t a2) {
    int evtype = syscall_to_evtype(syscall_nr, a0, a2);
    if (evtype < 0) return;

    std::string k = ev_key((std::uint8_t)evtype);
    double base = MathEng::llr_for(cfg_, k);
    if (base <= 0.0) return;

    int cat = ev_category((std::uint8_t)evtype);
    double t = now_sec();

    std::unique_lock<std::shared_mutex> lk(g_lock_);
    auto n = lookup_by_pid(tgid);
    if (!n) return;

    double mult = 1.0;
    if (n->owner_uid == 0) mult *= cfg_.ctx_uid0;
    double amount = base * mult;

    bool was_exempt = n->exempt;
    n->exempt = false;
    add_evidence(n, cat, amount, t);
    backprop(n, cat, amount, 0, t);
    n->exempt = was_exempt;

    char m[192];
    std::snprintf(m, sizeof(m), "[SECCOMP] pid=%u %s %s allowed llr=%.2f risk=%.1f%% st=%s",
                  n->pid, n->comm, k.c_str(), amount, n->risk_pct * 100.0,
                  active_stages(n).c_str());
    log_alert(m);
}

void Tracker::seccomp_persist_hash(std::uint32_t tgid, bool blacklist) {
    if (!rep_) return;
    std::string comm, path, hash;
    {
        std::shared_lock<std::shared_mutex> lk(g_lock_);
        auto n = lookup_by_pid(tgid);
        if (n) {
            comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
            hash = n->cached_hash;
            path = n->cached_path;
        }
        if (hash.empty()) {
            auto hit = tgid_hash_.find(tgid);
            if (hit != tgid_hash_.end()) hash = hit->second;
        }
        if (path.empty()) {
            auto pit = tgid_path_.find(tgid);
            if (pit != tgid_path_.end()) path = pit->second;
        }
    }
    TLOG("SEC-PERSIST tgid=%u node_hash=%d node_path=%d -> hash='%s' path='%s'",
         tgid, (int)!hash.empty(), (int)!path.empty(),
         hash.empty() ? "(none)" : "ok", path.empty() ? "(none)" : path.c_str());
    if (hash.empty() && !path.empty()) {
        bool ok = false;
        hash = Reputation::hash_of_file(path, ok);
        if (!ok) hash.clear();
        TLOG("SEC-PERSIST hash_of_file('%s') -> %d", path.c_str(), (int)ok);
    }
    if (path.empty()) path = rep_->resolve_exe(tgid);
    if (hash.empty()) {
        bool ok = false;
        hash = Reputation::hash_of_pid(tgid, ok);
        if (!ok) hash.clear();
        TLOG("SEC-PERSIST hash_of_pid(%u) -> %d", tgid, (int)ok);
    }
    if (comm.empty() && !path.empty()) {
        std::size_t sl = path.find_last_of('/');
        comm = (sl == std::string::npos) ? path : path.substr(sl + 1);
    }
    if (hash.empty()) {
        char m[128];
        std::snprintf(m, sizeof(m), "[SECCOMP] pid=%u hash persist FAILED (no readable exe)", tgid);
        log_alert(m);
        return;
    }
    std::uint8_t kind = blacklist ? REP_BLACKLIST : REP_WHITELIST;
    bool ok = rep_->add(kind, hash, comm, path);
    char m[192];
    std::snprintf(m, sizeof(m), "[SECCOMP] pid=%u %s -> %s %s",
                  tgid, comm.c_str(),
                  blacklist ? "BLACKLIST" : "WHITELIST",
                  ok ? "persisted" : "FAILED");
    log_alert(m);
}

void Tracker::seed_from_proc() {
    DIR *d = opendir("/proc");
    if (!d) return;
    struct SEntry { std::uint32_t pid, ppid, pgid; std::string comm; };
    std::vector<SEntry> entries;
    struct dirent *de;
    while ((de = readdir(d)) != nullptr) {
        char *end;
        long p = std::strtol(de->d_name, &end, 10);
        if (*end != '\0' || p <= 0) continue;
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%ld/stat", p);
        int fd = ::open(path, O_RDONLY);
        if (fd < 0) continue;
        char buf[512];
        ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
        ::close(fd);
        if (n <= 0) continue;
        buf[n] = 0;
        char *lp = std::strchr(buf, '(');
        char *rp = std::strrchr(buf, ')');
        if (!lp || !rp || lp >= rp) continue;
        SEntry se;
        se.pid = static_cast<std::uint32_t>(p);
        std::size_t clen = static_cast<std::size_t>(rp - lp - 1);
        if (clen >= MAX_COMM) clen = MAX_COMM - 1;
        se.comm.assign(lp + 1, clen);
        char state; unsigned ppid = 0, pgid = 0;
        if (std::sscanf(rp + 1, " %c %u %u", &state, &ppid, &pgid) != 3) continue;
        se.ppid = ppid; se.pgid = pgid;
        entries.push_back(std::move(se));
    }
    closedir(d);

    std::unique_lock<std::shared_mutex> lk(g_lock_);
    double t = now_sec();
    int seeded_edr = 0;
    for (auto &se : entries) {
        auto n = std::make_shared<ProcNode>();
        n->uid = std::to_string(se.pid) + "_seed";
        n->pid = se.pid; n->tgid = se.pid; n->ppid = se.ppid; n->pgid = se.pgid;
        n->is_new = false;
        std::size_t clen = std::min(se.comm.size(), (std::size_t)(MAX_COMM - 1));
        std::memcpy(n->comm, se.comm.data(), clen);
        n->comm[clen] = 0;
        n->exempt = self_pid(se.pid, se.pgid) || is_exempt_comm(n->comm);
        if (n->exempt) kernel_exempt(se.pid, true);
        n->created_ts = t; n->last_ev_ts = t; n->last_score_ts = t;
        if (std::strncmp(n->comm, "edr", 3) == 0) {
            seeded_edr++;
            TLOG("SEED edr node pid=%u ppid=%u pgid=%u exempt=%d", se.pid, se.ppid, se.pgid, (int)n->exempt);
        }
        nodes_[n->uid] = n;
        pid_to_uid_[se.pid] = n->uid;
    }
    for (auto &se : entries) {
        auto it = pid_to_uid_.find(se.pid);
        if (it == pid_to_uid_.end()) continue;
        auto n = nodes_[it->second];
        if (se.ppid > 0) {
            auto pit = pid_to_uid_.find(se.ppid);
            if (pit != pid_to_uid_.end() && pit->second != n->uid) {
                auto p = nodes_[pit->second];
                n->parent = p; p->children.push_back(n);
                continue;
            }
        }
        roots_.push_back(n);
    }
    TLOG("SEED done: %zu nodes, %d named edr, %zu roots", nodes_.size(), seeded_edr, roots_.size());
}

std::shared_ptr<ProcNode> Tracker::lookup_by_pid(std::uint32_t tgid) {
    auto it = pid_to_uid_.find(tgid);
    if (it == pid_to_uid_.end()) return nullptr;
    auto nit = nodes_.find(it->second);
    if (nit == nodes_.end()) return nullptr;
    return nit->second;
}

std::shared_ptr<ProcNode> Tracker::fork_node(const edr_event &e) {
    auto pit = pid_to_uid_.find(e.tgid);
    if (pit != pid_to_uid_.end()) {
        auto old = nodes_.find(pit->second);
        if (old != nodes_.end()) {
            old->second->is_dead = true;
            old->second->died_ts = ns_to_sec(e.ts_ns);
        }
    }
    auto n = std::make_shared<ProcNode>();
    n->uid = mk_uid(e.tgid, e.ts_ns);
    n->pid = e.pid; n->tgid = e.tgid; n->ppid = e.ppid; n->pgid = e.pgid;
    n->owner_uid = e.uid; n->ns_inum = e.ns_inum;
    n->is_new = true;
    std::memcpy(n->comm, e.comm, MAX_COMM);
    n->exempt = self_pid(e.pid, e.pgid) || is_exempt_comm(n->comm);
    if (n->exempt) kernel_exempt(n->tgid, true);
    double t = ns_to_sec(e.ts_ns);
    n->created_ts = t; n->last_ev_ts = t; n->last_score_ts = t;
    if (supervised_roots_.count(e.ppid) || supervised_roots_.count(e.tgid))
        n->supervised = true;
    auto par = lookup_by_pid(e.ppid);
    bool par_found = (bool)par;
    bool synthed = false;
    if (par) {
        n->parent = par; par->children.push_back(n);
        if (par->supervised || supervised_roots_.count(par->tgid)) n->supervised = true;
    }
    else {
        auto sn = synth_node(e.ppid, supervised_roots_.count(e.ppid) > 0);
        if (sn) { n->parent = sn; sn->children.push_back(n); if (sn->supervised) n->supervised = true; synthed = true; }
        else roots_.push_back(n);
    }
    nodes_[n->uid] = n;
    pid_to_uid_[e.tgid] = n->uid;
    TLOG("FORK-NODE pid=%u tgid=%u ppid=%u pgid=%u comm='%.16s' exempt=%d sup=%d par=%d synth=%d root=%d",
         e.pid, e.tgid, e.ppid, e.pgid, e.comm, (int)n->exempt, (int)n->supervised,
         (int)par_found, (int)synthed, (int)(!par_found && !synthed));
    return n;
}

std::shared_ptr<ProcNode> Tracker::synth_node(std::uint32_t tgid, bool supervised) {
    if (tgid == 0) return nullptr;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%u/stat", tgid);
    int fd = ::open(path, O_RDONLY);
    if (fd < 0) { TLOG("SYNTH tgid=%u FAILED (no /proc)", tgid); return nullptr; }
    char buf[512];
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) { TLOG("SYNTH tgid=%u FAILED (read)", tgid); return nullptr; }
    buf[n] = 0;
    char *lp = std::strchr(buf, '(');
    char *rp = std::strrchr(buf, ')');
    if (!lp || !rp || lp >= rp) { TLOG("SYNTH tgid=%u FAILED (parse)", tgid); return nullptr; }
    char state; unsigned ppid = 0, pgid = 0;
    if (std::sscanf(rp + 1, " %c %u %u", &state, &ppid, &pgid) != 3) { TLOG("SYNTH tgid=%u FAILED (scan)", tgid); return nullptr; }

    auto sn = std::make_shared<ProcNode>();
    double t = now_sec();
    sn->uid = mk_uid(tgid, (std::uint64_t)(t * 1e9));
    sn->pid = tgid; sn->tgid = tgid; sn->ppid = ppid; sn->pgid = pgid;
    sn->is_new = true;
    std::size_t clen = static_cast<std::size_t>(rp - lp - 1);
    if (clen >= MAX_COMM) clen = MAX_COMM - 1;
    std::memcpy(sn->comm, lp + 1, clen);
    sn->comm[clen] = 0;
    sn->supervised = supervised;
    sn->exempt = supervised ? false : (self_pid(tgid, pgid) || is_exempt_comm(sn->comm));
    sn->created_ts = t; sn->last_ev_ts = t; sn->last_score_ts = t;

    auto par = lookup_by_pid(ppid);
    if (par) { sn->parent = par; par->children.push_back(sn); }
    else roots_.push_back(sn);

    nodes_[sn->uid] = sn;
    pid_to_uid_[tgid] = sn->uid;
    TLOG("SYNTH-NODE tgid=%u ppid=%u pgid=%u comm='%.16s' exempt=%d sup=%d par=%d",
         tgid, ppid, pgid, sn->comm, (int)sn->exempt, (int)sn->supervised, (int)(bool)par);
    return sn;
}

std::shared_ptr<ProcNode> Tracker::ensure_node(const edr_event &e) {
    auto n = lookup_by_pid(e.tgid);
    if (n) return n;
    auto sn = std::make_shared<ProcNode>();
    sn->uid = mk_uid(e.tgid, e.ts_ns);
    sn->pid = e.pid; sn->tgid = e.tgid; sn->ppid = e.ppid; sn->pgid = e.pgid;
    sn->owner_uid = e.uid; sn->ns_inum = e.ns_inum;
    sn->is_new = false;
    std::memcpy(sn->comm, e.comm, MAX_COMM);
    sn->exempt = self_pid(e.pid, e.pgid) || is_exempt_comm(sn->comm);
    if (sn->exempt) kernel_exempt(sn->tgid, true);
    double t = ns_to_sec(e.ts_ns);
    sn->created_ts = t; sn->last_ev_ts = t; sn->last_score_ts = t;
    if (supervised_roots_.count(e.ppid) || supervised_roots_.count(e.tgid))
        sn->supervised = true;
    auto par = lookup_by_pid(e.ppid);
    bool par_found = (bool)par;
    bool synthed = false;
    if (par) {
        sn->parent = par; par->children.push_back(sn);
        if (par->supervised || supervised_roots_.count(par->tgid)) sn->supervised = true;
    }
    else {
        auto pn = synth_node(e.ppid, supervised_roots_.count(e.ppid) > 0);
        if (pn) { sn->parent = pn; pn->children.push_back(sn); if (pn->supervised) sn->supervised = true; synthed = true; }
        else roots_.push_back(sn);
    }
    nodes_[sn->uid] = sn;
    pid_to_uid_[e.tgid] = sn->uid;
    TLOG("ENSURE-NODE ev=%s pid=%u tgid=%u ppid=%u pgid=%u comm='%.16s' exempt=%d sup=%d par=%d synth=%d root=%d",
         evname(e.ev_type), e.pid, e.tgid, e.ppid, e.pgid, e.comm,
         (int)sn->exempt, (int)sn->supervised, (int)par_found, (int)synthed,
         (int)(!par_found && !synthed));
    return sn;
}

double Tracker::ctx_mult(const edr_event &e, const std::shared_ptr<ProcNode> &n) const {
    double m = 1.0;
    if (e.uid == 0) m *= cfg_.ctx_uid0;
    if (n && n->ns_inum != 0 && e.ns_inum != 0 && n->ns_inum != e.ns_inum) m *= cfg_.ctx_ns;
    if (n) {
        double age = ns_to_sec(e.ts_ns) - n->created_ts;
        if (age >= 0.0 && age < 1.0) m *= cfg_.ctx_short;
    }
    return m;
}

void Tracker::decay_to(const std::shared_ptr<ProcNode> &n, double now) {
    if (!n) return;
    double dt = now - n->last_score_ts;
    if (dt <= 0.0) return;
    for (int c = 0; c < CAT_COUNT; c++)
        n->cat_accum[c] = MathEng::decay_accum(n->cat_accum[c], dt, cfg_.cats[c].half_life);
    n->last_score_ts = now;
}

void Tracker::recompute(const std::shared_ptr<ProcNode> &n) {
    if (!n) return;
    double S = cfg_.prior_logodds;
    if (!n->is_new) S += cfg_.seeded_prior_extra;
    int n_active = 0;
    for (int c = 0; c < CAT_COUNT; c++) {
        double contrib = MathEng::cat_contrib(n->cat_accum[c], cfg_.cats[c].max_llr, cfg_.cats[c].scale);
        S += contrib;
        if (contrib >= cfg_.active_floor) n_active++;
    }
    if (n_active >= 2) S += cfg_.corrob_coeff * (n_active - 1);
    n->logodds = S;
    n->risk_pct = MathEng::sigmoid_stable(S);
    if (n->risk_pct > n->peak_risk_pct) n->peak_risk_pct = n->risk_pct;
}

void Tracker::add_evidence(const std::shared_ptr<ProcNode> &n, int cat, double amount, double now) {
    if (!n || n->exempt || amount <= 0.0) return;
    decay_to(n, now);
    n->cat_accum[cat] += amount;
    n->last_ev_ts = now;
    recompute(n);
    update_watchlist(n);
}

void Tracker::backprop(const std::shared_ptr<ProcNode> &n, int cat, double amount, int depth, double now) {
    if (!n || depth >= cfg_.backprop_max_depth) return;
    auto p = n->parent.lock();
    if (!p || p->exempt) return;
    double prop = amount * cfg_.backprop_factor;
    if (prop < 0.05) return;
    add_evidence(p, cat, prop, now);
    backprop(p, cat, prop, depth + 1, now);
}

std::shared_ptr<ProcNode> Tracker::responsible_launcher(const std::shared_ptr<ProcNode> &src) {
    auto node = src->parent.lock();
    std::shared_ptr<ProcNode> launcher;
    int guard = 0;
    while (node && guard++ < 256) {
        if (!node->exempt) launcher = node;
        node = node->parent.lock();
    }
    return launcher;
}

void Tracker::recompute_badges() {
    for (auto &kv : nodes_) if (kv.second) kv.second->badge_risk = 0.0;
    for (auto &kv : nodes_) {
        auto &n = kv.second;
        if (!n || n->exempt) continue;
        if (n->risk_pct < cfg_.badge_floor) continue;
        auto L = responsible_launcher(n);
        if (L && !L->exempt && L.get() != n.get()) {
            if (n->risk_pct > L->badge_risk) L->badge_risk = n->risk_pct;
        }
    }
    for (auto &kv : nodes_) {
        auto &n = kv.second;
        if (!n) continue;
        if (n->badge_risk > n->badge_peak) n->badge_peak = n->badge_risk;
    }
}

std::string Tracker::active_stages(const std::shared_ptr<ProcNode> &n) const {
    static const char L[CAT_COUNT] = { 'L', 'X', 'M', 'P', 'E', 'C' };
    std::string s;
    for (int c = 0; c < CAT_COUNT; c++) {
        double contrib = MathEng::cat_contrib(n->cat_accum[c], cfg_.cats[c].max_llr, cfg_.cats[c].scale);
        if (contrib >= cfg_.active_floor) s += L[c];
    }
    return s;
}

std::string Tracker::compute_origin(const std::shared_ptr<ProcNode> &n) const {
    std::string origin(n->comm, ::strnlen(n->comm, MAX_COMM));
    auto cur = n->parent.lock();
    int guard = 0;
    while (cur && guard++ < 256) {
        if (!cur->exempt) origin.assign(cur->comm, ::strnlen(cur->comm, MAX_COMM));
        cur = cur->parent.lock();
    }
    return origin;
}

bool Tracker::session_allowed(const FileId &id) const {
    if (!id.valid() || session_allow_.empty()) return false;
    auto it = session_allow_.find(id.key());
    return it != session_allow_.end() && !it->second.paused;
}

void Tracker::recompute_exempt(const std::shared_ptr<ProcNode> &n) {
    if (!n) return;
    bool ex = self_pid(n->pid, n->pgid) || is_exempt_comm(n->comm) || session_allowed(n->fid);
    if (!ex && rep_ && !n->cached_hash.empty() && rep_->is_whitelisted(n->cached_hash)) ex = true;
    n->exempt = ex;
    kernel_exempt(n->tgid, ex);
}

void Tracker::apply_session_locked(const std::string &key) {
    for (auto &kv : nodes_) {
        auto &m = kv.second;
        if (!m || m->is_dead) continue;
        if (!m->fid.valid() || m->fid.key() != key) continue;
        recompute_exempt(m);
    }
}

std::vector<SessionEntry> Tracker::session_list() const {
    std::shared_lock<std::shared_mutex> lk(g_lock_);
    std::vector<SessionEntry> out;
    out.reserve(session_allow_.size());
    for (auto &kv : session_allow_) out.push_back(kv.second);
    std::sort(out.begin(), out.end(), [](const SessionEntry &a, const SessionEntry &b) {
        return a.added_tstr > b.added_tstr;
    });
    return out;
}

bool Tracker::session_set_paused(const std::string &key, bool paused) {
    std::string name;
    {
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        auto it = session_allow_.find(key);
        if (it == session_allow_.end()) return false;
        it->second.paused = paused;
        name = it->second.name;
        apply_session_locked(key);
    }
    log_alert(std::string("[SESSION] ") + name + (paused ? " paused (now scored again)"
                                                         : " resumed (trusted again)"));
    return true;
}

bool Tracker::session_remove(const std::string &key) {
    std::string name;
    {
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        auto it = session_allow_.find(key);
        if (it == session_allow_.end()) return false;
        name = it->second.name;
        session_allow_.erase(it);
        apply_session_locked(key);
    }
    log_alert("[SESSION] " + name + " removed (now scored again)");
    return true;
}

void Tracker::enqueue_prompt(const std::shared_ptr<ProcNode> &n, const std::string &action, bool burst) {
    if (!n) return;
    bool inherited = false;
    if (!n->fid.valid()) {
        auto fit = tgid_fid_.find(n->tgid);
        if (fit != tgid_fid_.end()) n->fid = fit->second;
    }
    if (!n->fid.valid()) {
        auto cur = n->parent.lock();
        int guard = 0;
        while (cur && guard++ < 32) {
            FileId cand;
            if (cur->fid.valid()) cand = cur->fid;
            else {
                auto fit = tgid_fid_.find(cur->tgid);
                if (fit != tgid_fid_.end()) cand = fit->second;
            }
            if (cand.valid()) {
                n->fid = cand;
                inherited = true;
                if (n->cached_path.empty()) {
                    if (!cur->cached_path.empty()) n->cached_path = cur->cached_path;
                    else {
                        auto pit = tgid_path_.find(cur->tgid);
                        if (pit != tgid_path_.end()) n->cached_path = pit->second;
                    }
                }
                TLOG("PROMPT-INHERIT tgid=%u <- ancestor tgid=%u fid=%s",
                     n->tgid, cur->tgid, cand.key().c_str());
                break;
            }
            cur = cur->parent.lock();
        }
    }
    if (session_allowed(n->fid)) {
        n->exempt = true;
        n->frozen = false;
        n->prompt_pending = false;
        kernel_exempt(n->tgid, true);
        disarm_block(n->tgid);
        if (n->pgid > 1 && n->pgid != own_pgid_)
            ::kill(-static_cast<pid_t>(n->pgid), SIGCONT);
        TLOG("ENQUEUE-PROMPT SKIP tgid=%u session-allowed fid=%s",
             n->tgid, n->fid.key().c_str());
        return;
    }
    if (n->cached_hash.empty()) {
        auto hit = tgid_hash_.find(n->tgid);
        if (hit != tgid_hash_.end()) n->cached_hash = hit->second;
        else if (hasher_ && n->fid.valid()) {
            std::string h;
            if (hasher_->lookup(n->fid, h)) { n->cached_hash = h; tgid_hash_[n->tgid] = h; }
        }
    }
    if (n->cached_path.empty()) {
        auto pit = tgid_path_.find(n->tgid);
        if (pit != tgid_path_.end()) n->cached_path = pit->second;
    }
    TLOG("ENQUEUE-PROMPT tgid=%u pid=%u pgid=%u comm='%.16s' risk=%.3f burst=%d fid_valid=%d hash=%d inherited=%d path='%s'",
         n->tgid, n->pid, n->pgid, n->comm, n->risk_pct, (int)burst,
         (int)n->fid.valid(), (int)!n->cached_hash.empty(), (int)inherited,
         n->cached_path.empty() ? "(none)" : n->cached_path.c_str());
    PromptReq r;
    r.uid = n->uid; r.pid = n->pid; r.pgid = n->pgid;
    r.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
    r.origin = compute_origin(n);
    r.doing = action;
    r.risk = n->risk_pct;
    r.from_burst = burst;
    r.hash = n->cached_hash;
    r.path = n->cached_path;
    r.identity_ready = !n->cached_hash.empty() || n->fid.valid();
    r.allow_lbl = act_desc(cfg_.allow_action);
    r.deny_lbl = act_desc(cfg_.deny_action);
    r.kill_lbl = act_desc(cfg_.kill_action);
    r.wl_lbl = act_desc(cfg_.whitelist_action);
    std::lock_guard<std::mutex> lk(prompt_mtx_);
    if (prompt_q_.size() < 32) prompt_q_.push_back(std::move(r));
}

std::optional<PromptReq> Tracker::take_prompt() {
    std::lock_guard<std::mutex> lk(prompt_mtx_);
    if (prompt_q_.empty()) return std::nullopt;
    PromptReq r = prompt_q_.front();
    prompt_q_.pop_front();
    return r;
}

bool Tracker::arm_block(std::uint32_t tgid) {
    if (block_map_fd_ < 0 || tgid == 0) return false;
    struct blk_val v{};
    v.armed_ns = static_cast<std::uint64_t>(now_sec() * 1e9);
    v.mode = 0;
    return bpf_map_update_elem(block_map_fd_, &tgid, &v, BPF_ANY) == 0;
}

void Tracker::disarm_block(std::uint32_t tgid) {
    if (block_map_fd_ < 0 || tgid == 0) return;
    bpf_map_delete_elem(block_map_fd_, &tgid);
}

void Tracker::set_enforcement_fds(int block_fd, int switch_fd) {
    block_map_fd_ = block_fd;
    enforce_switch_fd_ = switch_fd;
}

void Tracker::set_burst_fds(int epoch_fd, int exempt_fd) {
    burst_epoch_fd_ = epoch_fd;
    exempt_fd_ = exempt_fd;
}

void Tracker::set_enforcement(bool on) {
    enforce_on_.store(on);
    if (enforce_switch_fd_ >= 0) {
        std::uint32_t k = 0, v = on ? 1u : 0u;
        bpf_map_update_elem(enforce_switch_fd_, &k, &v, BPF_ANY);
    }
    log_alert(std::string("[LSM] enforcement ")
              + (on ? "ENABLED" : "DISABLED (all blocks bypassed)"));
}

void Tracker::flush_blocks() {
    if (block_map_fd_ >= 0) {
        std::vector<std::uint32_t> keys;
        std::uint32_t cur = 0, nxt = 0;
        void *pk = nullptr;
        while (bpf_map_get_next_key(block_map_fd_, pk, &nxt) == 0) {
            keys.push_back(nxt); cur = nxt; pk = &cur;
        }
        for (auto k : keys) bpf_map_delete_elem(block_map_fd_, &k);
    }
    std::unique_lock<std::shared_mutex> lk(g_lock_);
    for (auto &kv : nodes_) if (kv.second) kv.second->blocked = false;
    log_alert("[LSM] all blocks cleared");
}

std::size_t Tracker::blocks_active() const {
    std::shared_lock<std::shared_mutex> lk(g_lock_);
    std::size_t n = 0;
    for (auto &kv : nodes_)
        if (kv.second && kv.second->blocked && !kv.second->is_dead) n++;
    return n;
}

void Tracker::reblock_from_reputation(const std::string &hash) {
    std::vector<std::uint32_t> hits;
    {
        std::shared_lock<std::shared_mutex> lk(g_lock_);
        for (auto &kv : tgid_hash_)
            if (kv.second == hash) hits.push_back(kv.first);
    }
    for (auto tg : hits) {
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        auto n = lookup_by_pid(tg);
        if (n && !n->is_dead && !n->exempt) {
            arm_block(tg);
            n->blocked = true;
            rep_blocks_.fetch_add(1);
            char msg[192];
            std::snprintf(msg, sizeof(msg),
                "[REP-BLOCK] pid=%u %s re-blocked (blacklist rule active)",
                n->pid, n->comm);
            log_alert(msg);
        }
    }
}

void Tracker::unblock_hash_live(const std::string &hash) {
    std::vector<std::uint32_t> hits;
    {
        std::shared_lock<std::shared_mutex> lk(g_lock_);
        for (auto &kv : tgid_hash_)
            if (kv.second == hash) hits.push_back(kv.first);
    }
    for (auto tg : hits) {
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        auto n = lookup_by_pid(tg);
        if (n && n->blocked) {
            disarm_block(tg);
            n->blocked = false;
            char msg[192];
            std::snprintf(msg, sizeof(msg),
                "[REP] pid=%u %s block lifted (rule removed/paused)", n->pid, n->comm);
            log_alert(msg);
        }
    }
}

void Tracker::resolve_prompt(const std::string &uid, std::uint32_t pgid, char decision) {
    TLOG("RESOLVE uid=%s pgid=%u decision=%c", uid.c_str(), pgid, decision);
    if (decision == 'b') {
        std::string comm; std::uint32_t tgid = 0;
        {
            std::unique_lock<std::shared_mutex> lk(g_lock_);
            auto it = nodes_.find(uid);
            if (it != nodes_.end() && it->second) {
                auto &n = it->second;
                comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
                tgid = n->tgid;
                if (pgid == 0) pgid = n->pgid;
                n->prompt_pending = false;
                n->frozen = false;
                n->blocked = true;
                n->last_score_ts = now_sec();
            }
        }
        bool armed = arm_block(tgid);
        if (pgid > 1 && pgid != own_pgid_) ::kill(-static_cast<pid_t>(pgid), SIGCONT);
        log_alert(armed
            ? "[BLOCK] " + comm + " resumed; risky syscalls denied in-kernel (LSM)"
            : "[BLOCK] " + comm + " arm FAILED (enforcement unavailable)");
        return;
    }

    if (decision == 'd' || decision == 'l') {
        std::uint8_t kind = (decision == 'd') ? REP_BLACKLIST : REP_WHITELIST;
        std::string comm, hash, path;
        std::uint32_t tgid = 0;
        FileId fid;
        {
            std::unique_lock<std::shared_mutex> lk(g_lock_);
            auto it = nodes_.find(uid);
            if (it != nodes_.end() && it->second) {
                auto &n = it->second;
                comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
                tgid = n->tgid;
                fid = n->fid;
                hash = n->cached_hash;
                path = n->cached_path;
                if (pgid == 0) pgid = n->pgid;
                n->prompt_pending = false;
            }
            if (hash.empty()) {
                auto hit = tgid_hash_.find(tgid);
                if (hit != tgid_hash_.end()) hash = hit->second;
            }
            if (path.empty()) {
                auto pit = tgid_path_.find(tgid);
                if (pit != tgid_path_.end()) path = pit->second;
            }
            if (!fid.valid()) {
                auto fit = tgid_fid_.find(tgid);
                if (fit != tgid_fid_.end()) fid = fit->second;
            }
        }
        if (hash.empty() && hasher_ && fid.valid()) {
            std::string h;
            if (hasher_->wait_for(fid, h, 3000)) hash = h;
            TLOG("RESOLVE-REP wait_for(%s) -> %d", fid.key().c_str(), (int)!hash.empty());
        }
        if (hash.empty() && !path.empty()) {
            bool ok = false;
            std::string h = Reputation::hash_of_file(path, ok);
            if (ok) hash = h;
            TLOG("RESOLVE-REP hash_of_file('%s') -> %d", path.c_str(), (int)ok);
        }
        if (comm.empty() && !path.empty()) {
            std::size_t sl = path.find_last_of('/');
            comm = (sl == std::string::npos) ? path : path.substr(sl + 1);
        }
        bool ok = false;
        if (rep_ && !hash.empty()) {
            ok = rep_->add(kind, hash, comm, path);
            std::unique_lock<std::shared_mutex> lk(g_lock_);
            tgid_hash_[tgid] = hash;
        }
        TLOG("RESOLVE-REP final tgid=%u fid_valid=%d hash=%d ok=%d",
             tgid, (int)fid.valid(), (int)!hash.empty(), (int)ok);
        if (kind == REP_BLACKLIST) {
            {
                std::unique_lock<std::shared_mutex> lk(g_lock_);
                auto it = nodes_.find(uid);
                if (it != nodes_.end() && it->second) { it->second->frozen = false; it->second->blocked = true; }
            }
            arm_block(tgid);
            if (pgid > 1 && pgid != own_pgid_) ::kill(-static_cast<pid_t>(pgid), SIGCONT);
            log_alert(ok
                ? "[BLACKLIST] " + comm + " hash persisted; blocked & resumed"
                : "[BLACKLIST] " + comm + " FAILED to persist (binary identity unrecoverable)");
        } else {
            {
                std::unique_lock<std::shared_mutex> lk(g_lock_);
                auto it = nodes_.find(uid);
                if (it != nodes_.end() && it->second) {
                    it->second->frozen = false; it->second->exempt = true; it->second->blocked = false;
                    kernel_exempt(it->second->tgid, true);
                }
            }
            disarm_block(tgid);
            if (pgid > 1 && pgid != own_pgid_) ::kill(-static_cast<pid_t>(pgid), SIGCONT);
            log_alert(ok
                ? "[WHITELIST+] " + comm + " hash persisted; exempted & resumed"
                : "[WHITELIST+] " + comm + " FAILED to persist (binary identity unrecoverable)");
        }
        return;
    }

    if (decision == 'w') {
        std::string comm, path;
        std::uint32_t tgid = 0;
        FileId fid;
        std::size_t affected = 0, binaries = 0;
        {
            std::unique_lock<std::shared_mutex> lk(g_lock_);
            auto it = nodes_.find(uid);
            if (it != nodes_.end() && it->second) {
                auto &n = it->second;
                comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
                tgid = n->tgid;
                fid = n->fid;
                path = n->cached_path;
                if (pgid == 0) pgid = n->pgid;
            }
            if (!fid.valid()) {
                auto f2 = tgid_fid_.find(tgid);
                if (f2 != tgid_fid_.end()) fid = f2->second;
            }
            if (path.empty()) {
                auto p2 = tgid_path_.find(tgid);
                if (p2 != tgid_path_.end()) path = p2->second;
            }
            if (fid.valid()) {
                auto sit = session_allow_.find(fid.key());
                if (sit == session_allow_.end()) {
                    SessionEntry se;
                    se.key = fid.key();
                    se.name = comm;
                    se.path = path;
                    se.added_tstr = now_hms_ms();
                    se.paused = false;
                    session_allow_[se.key] = se;
                } else {
                    sit->second.paused = false;
                    if (sit->second.path.empty()) sit->second.path = path;
                }
            }
            binaries = session_allow_.size();
            for (auto &kv : nodes_) {
                auto &m = kv.second;
                if (!m || m->is_dead) continue;
                bool match = fid.valid() && m->fid.valid() && m->fid.key() == fid.key();
                if (!match && m->tgid != tgid) continue;
                m->exempt = true;
                m->blocked = false;
                m->frozen = false;
                m->prompt_pending = false;
                kernel_exempt(m->tgid, true);
                disarm_block(m->tgid);
                affected++;
            }
        }
        if (pgid > 1 && pgid != own_pgid_) ::kill(-static_cast<pid_t>(pgid), SIGCONT);
        TLOG("SESSION-ALLOW tgid=%u fid_valid=%d affected=%zu binaries=%zu",
             tgid, (int)fid.valid(), affected, binaries);
        char m[224];
        if (fid.valid())
            std::snprintf(m, sizeof(m),
                "[SESSION-ALLOW] %s trusted until restart (%zu live process(es))",
                comm.c_str(), affected);
        else
            std::snprintf(m, sizeof(m),
                "[SESSION-ALLOW] %s resumed, but binary identity unknown - only this process is trusted",
                comm.c_str());
        log_alert(m);
        return;
    }

    std::string action; const char *dn;
    switch (decision) {
        case 'y': action = cfg_.allow_action; dn = "ALLOW"; break;
        case 'n': action = cfg_.deny_action; dn = "DENY"; break;
        case 'k': action = cfg_.kill_action; dn = "KILL"; break;
        case 'w': action = cfg_.whitelist_action; dn = "WHITELIST"; break;
        default:  action = "none"; dn = "DISMISS"; break;
    }
    int a = act_index(action);
    std::string comm;
    std::uint32_t tgid = 0;
    {
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        auto it = nodes_.find(uid);
        if (it != nodes_.end() && it->second) {
            auto &n = it->second;
            comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
            tgid = n->tgid;
            if (pgid == 0) pgid = n->pgid;
            n->prompt_pending = false;
            n->last_score_ts = now_sec();
            if (a == PA_RESUME || a == PA_WHITELIST) n->frozen = false;
            if (a == PA_FREEZE) n->frozen = true;
            if (a == PA_WHITELIST) { n->exempt = true; n->blocked = false; kernel_exempt(n->tgid, true); }
        }
    }
    if ((a == PA_RESUME || a == PA_WHITELIST || a == PA_KILL) && tgid != 0) {
        disarm_block(tgid);
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        auto it = nodes_.find(uid);
        if (it != nodes_.end() && it->second) it->second->blocked = false;
    }
    bool ok = (pgid > 1 && pgid != own_pgid_);
    switch (a) {
        case PA_RESUME:
            if (ok) ::kill(-static_cast<pid_t>(pgid), SIGCONT);
            log_alert(std::string("[") + dn + "->RESUME] " + comm + " resumed (SIGCONT)");
            break;
        case PA_FREEZE:
            if (ok) ::kill(-static_cast<pid_t>(pgid), SIGSTOP);
            log_alert(std::string("[") + dn + "->FREEZE] " + comm + " kept suspended (SIGSTOP)");
            break;
        case PA_KILL:
            if (ok) { ::kill(-static_cast<pid_t>(pgid), SIGKILL); kills_.fetch_add(1); }
            log_alert(std::string("[") + dn + "->KILL] " + comm + " terminated (SIGKILL)");
            break;
        case PA_WHITELIST:
            if (ok) ::kill(-static_cast<pid_t>(pgid), SIGCONT);
            log_alert(std::string("[") + dn + "->WHITELIST] " + comm + " whitelisted & resumed");
            break;
        default:
            log_alert(std::string("[") + dn + "] " + comm + " no action taken");
            break;
    }
}

void Tracker::update_watchlist(const std::shared_ptr<ProcNode> &n) {
    if (!n || n->exempt || n->peak_risk_pct < WATCH_THRESHOLD) return;
    auto it = watchlist_.find(n->uid);
    if (it == watchlist_.end()) {
        if (watchlist_.size() >= WATCH_MAX) {
            auto lowest = watchlist_.begin();
            for (auto i = watchlist_.begin(); i != watchlist_.end(); ++i)
                if (i->second.peak_risk_pct < lowest->second.peak_risk_pct) lowest = i;
            if (lowest->second.peak_risk_pct >= n->peak_risk_pct) return;
            watchlist_.erase(lowest);
        }
        WatchEntry w;
        w.uid = n->uid; w.pid = n->pid;
        w.first_tstr = now_hms_ms();
        w.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
        w.origin = compute_origin(n);
        w.stages = active_stages(n);
        w.peak_risk_pct = n->peak_risk_pct;
        w.current_risk_pct = n->risk_pct;
        w.child_count = n->children.size();
        w.is_dead = n->is_dead;
        watchlist_[n->uid] = std::move(w);
    } else {
        it->second.peak_risk_pct = n->peak_risk_pct;
        it->second.current_risk_pct = n->risk_pct;
        it->second.child_count = n->children.size();
        it->second.is_dead = n->is_dead;
        it->second.stages = active_stages(n);
        it->second.origin = compute_origin(n);
        it->second.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
    }
}

void Tracker::log_masquerade(const std::shared_ptr<ProcNode> &n, const char *new_name, bool susp) {
    if (!n || !new_name || !new_name[0]) return;
    if (std::strncmp(new_name, n->comm, MAX_COMM) == 0) return;
    MasqEvent m;
    m.tstr = now_hms_ms();
    m.pid = n->pid;
    m.old_comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
    m.new_comm.assign(new_name, ::strnlen(new_name, MAX_COMM));
    m.risk_pct = n->risk_pct;
    m.suspicious = susp;
    masq_events_.push_back(m);
    if (masq_events_.size() > MASQ_CAP) masq_events_.pop_front();
    if (susp) {
        char msg[192];
        std::snprintf(msg, sizeof(msg), "[%u] MASQUERADE '%s' -> '%s'",
                      n->pid, m.old_comm.c_str(), m.new_comm.c_str());
        log_alert(msg);
    }
}

void Tracker::ingest(const edr_event &e) {
    ev_count_.fetch_add(1);
    if (e.ev_type == EV_EXEC) prime_identity(e);
    if (e.ev_type == EV_BURST_TRIP) {
        burst_trips_.fetch_add(1);
        {
            std::shared_lock<std::shared_mutex> lk(g_lock_);
            auto sn = lookup_by_pid(e.tgid);
            TLOG("BURST tgid=%u comm='%.16s' node=%d sup=%d",
                 e.tgid, e.comm, (int)(bool)sn, sn ? (int)node_is_supervised(sn) : -1);
            if (sn && node_is_supervised(sn)) {
                return;
            }
        }
        double w = (double)e.data.burst.weight_fp / (double)BURST_FP_SCALE;
        char msg[192];
        std::snprintf(msg, sizeof(msg),
            "[BURST] pid=%u %s auto-blocked in-kernel (weight %.1f in window)",
            e.pid, e.comm, w);
        log_alert(msg);
        std::string hash, path;
        int verdict;
        {
            std::unique_lock<std::shared_mutex> lk(g_lock_);
            auto n = lookup_by_pid(e.tgid);
            if (n) n->blocked = true;
            verdict = reputation_verdict(e.tgid, hash, path);
        }
        if (verdict == 1) {
            char m2[192];
            std::snprintf(m2, sizeof(m2),
                "[REP-BLOCK] pid=%u %s matches blacklist hash; block confirmed silently",
                e.pid, e.comm);
            log_alert(m2);
            rep_blocks_.fetch_add(1);
            return;
        }
        if (verdict == -1) {
            disarm_block(e.tgid);
            {
                std::unique_lock<std::shared_mutex> lk(g_lock_);
                auto n = lookup_by_pid(e.tgid);
                if (n) { n->blocked = false; n->exempt = true; kernel_exempt(n->tgid, true); }
            }
            char m2[192];
            std::snprintf(m2, sizeof(m2),
                "[REP-ALLOW] pid=%u %s matches whitelist hash; burst block lifted",
                e.pid, e.comm);
            log_alert(m2);
            return;
        }
        std::shared_ptr<ProcNode> n;
        {
            std::unique_lock<std::shared_mutex> lk(g_lock_);
            n = lookup_by_pid(e.tgid);
        }
        if (n && cfg_.prompt_enabled && !n->prompt_pending) {
            bool is_me = n->exempt || n->tgid == own_pid_ || self_pid(n->pid, n->pgid);
            std::uint32_t pg = n->pgid;
            TLOG("BURST-FREEZE-CHK tgid=%u pg=%u own_pgid=%u is_me=%d pass=%d",
                 n->tgid, pg, own_pgid_, (int)is_me, (int)(!is_me && pg > 1 && pg != own_pgid_));
            if (is_me) {
                disarm_block(n->tgid);
                std::unique_lock<std::shared_mutex> lk(g_lock_);
                n->blocked = false;
                n->exempt = true;
                kernel_exempt(n->tgid, true);
            } else if (pg > 1 && pg != own_pgid_) {
                ::kill(-static_cast<pid_t>(pg), SIGSTOP);
                std::unique_lock<std::shared_mutex> lk(g_lock_);
                n->frozen = true; n->prompt_pending = true;
                enqueue_prompt(n, "trip a burst of risky syscalls (auto-blocked)", true);
            }
        }
        return;
    }
    if (e.ev_type == EV_LSM_DENY) {
        denies_.fetch_add(1);
        const char *k = "syscall";
        switch (e.data.deny.klass) {
            case DK_EXEC:    k = "execve";            break;
            case DK_WX:      k = "W^X map/mprotect";  break;
            case DK_SETUID:  k = "setuid->root";      break;
            case DK_PTRACE:  k = "ptrace";            break;
            case DK_CONNECT: k = "tcp connect";       break;
        }
        char msg[192];
        std::snprintf(msg, sizeof(msg), "[LSM-DENY] pid=%u %s blocked %s (-EPERM)",
                      e.pid, e.comm, k);
        log_alert(msg);
        return;
    }
    std::unique_lock<std::shared_mutex> lk(g_lock_);
    std::shared_ptr<ProcNode> n;
    bool prctl_score = false;
    if (e.ev_type == EV_FORK) {
        n = fork_node(e);
        if (n) {
            std::uint32_t src = e.ppid;
            if (tgid_fid_.find(src) == tgid_fid_.end()) {
                auto par = n->parent.lock();
                if (par) src = par->tgid;
            }
            inherit_identity(n->tgid, src);
            auto fit = tgid_fid_.find(n->tgid);
            if (fit != tgid_fid_.end()) n->fid = fit->second;
            auto hit = tgid_hash_.find(n->tgid);
            if (hit != tgid_hash_.end()) n->cached_hash = hit->second;
            auto pit = tgid_path_.find(n->tgid);
            if (pit != tgid_path_.end()) n->cached_path = pit->second;
        }
        if (!n->exempt && session_allowed(n->fid)) {
                n->exempt = true;
                kernel_exempt(n->tgid, true);
            }
    } else if (e.ev_type == EV_EXIT) {
        n = lookup_by_pid(e.tgid);
        if (n) {
            n->is_dead = true;
            n->died_ts = ns_to_sec(e.ts_ns);
            n->frozen = false;
            n->prompt_pending = false;
            auto wit = watchlist_.find(n->uid);
            if (wit != watchlist_.end()) wit->second.is_dead = true;
            if (n->blocked) { n->blocked = false; disarm_block(n->tgid); }
            kernel_exempt(n->tgid, false);
            supervised_roots_.erase(n->tgid);
        }
        return;
    } else {
        n = ensure_node(e);
        if (n && e.pgid > 0) n->pgid = e.pgid;
        bool supervised = node_is_supervised(n);
        if (n && e.ev_type == EV_EXEC) {
            std::memcpy(n->comm, e.comm, MAX_COMM);
            n->cached_hash.clear();
            n->cached_path.clear();
            n->fid = FileId{};
            auto fit = tgid_fid_.find(n->tgid);
            if (fit != tgid_fid_.end()) n->fid = fit->second;
            auto hit = tgid_hash_.find(n->tgid);
            if (hit != tgid_hash_.end()) n->cached_hash = hit->second;
            auto pit = tgid_path_.find(n->tgid);
            if (pit != tgid_path_.end()) n->cached_path = pit->second;
            n->exempt = self_pid(n->pid, n->pgid) || is_exempt_comm(n->comm)
                        || session_allowed(n->fid);
            kernel_exempt(n->tgid, n->exempt);
            TLOG("EXEC-CAPTURE tgid=%u comm='%.16s' fid=%s hash=%d path='%s' exempt=%d sup=%d",
                 n->tgid, n->comm, n->fid.key().c_str(), (int)!n->cached_hash.empty(),
                 n->cached_path.empty() ? "(none)" : n->cached_path.c_str(),
                 (int)n->exempt, (int)supervised);
            if (!n->exempt && !supervised && !n->rep_checked) {
                n->rep_checked = true;
                std::string hash, path;
                int verdict = reputation_verdict(n->tgid, hash, path);
                if (verdict == 1) {
                    arm_block(n->tgid);
                    n->blocked = true;
                    rep_blocks_.fetch_add(1);
                    char msg[192];
                    std::snprintf(msg, sizeof(msg),
                        "[REP-BLOCK] pid=%u %s known-bad hash on exec; blocked silently",
                        n->pid, n->comm);
                    log_alert(msg);
                } else if (verdict == -1) {
                    n->exempt = true;
                    kernel_exempt(n->tgid, true);
                    char msg[192];
                    std::snprintf(msg, sizeof(msg),
                        "[REP-ALLOW] pid=%u %s known-good hash on exec; exempted silently",
                        n->pid, n->comm);
                    log_alert(msg);
                }
            }
        }
        if (n && e.ev_type == EV_PRCTL_RENAME && !n->exempt) {
            char nn[MAX_COMM] = {0};
            std::memcpy(nn, e.data.rename.new_name, MAX_COMM - 1);
            prctl_score = is_masq_name(nn);
            log_masquerade(n, nn, prctl_score);
        }
    }
    if (!n || n->exempt || n->frozen) return;
    std::string k = ev_key(e.ev_type);
    if (e.ev_type == EV_PRCTL_RENAME && !prctl_score) return;
    double base = MathEng::llr_for(cfg_, k);
    if (base <= 0.0) return;
    double c = ctx_mult(e, n);
    double amount = base * c;
    int cat = ev_category(e.ev_type);
    double t = ns_to_sec(e.ts_ns);
    if (t <= 0.0) t = now_sec();
    add_evidence(n, cat, amount, t);
    backprop(n, cat, amount, 0, now_sec());
    bool supervised = node_is_supervised(n);
    if (base >= 1.5 && !supervised) {
        char msg[192];
        std::snprintf(msg, sizeof(msg), "[%u] %s %s llr=%.2f risk=%.1f%% st=%s",
            n->pid, n->comm, k.c_str(), amount, n->risk_pct * 100.0,
            active_stages(n).c_str());
        log_alert(msg);
    }
    double tw = now_sec();
    bool warm = (tw - start_ts_) >= cfg_.warmup_sec;
    bool gate_sup   = !supervised;
    bool gate_en    = cfg_.prompt_enabled;
    bool gate_warm  = warm;
    bool gate_pend  = !n->prompt_pending;
    bool gate_floor = base >= cfg_.prompt_event_floor;
    bool gate_thr   = n->risk_pct >= cfg_.prompt_threshold;
    bool gate_self  = !(n->tgid == own_pid_ || self_pid(n->pid, n->pgid));
    if (gate_thr && gate_floor) {
        TLOG("PROMPT-GATE ev=%s tgid=%u comm='%.16s' risk=%.3f base=%.2f | sup=%d en=%d warm=%d pend=%d floor=%d thr=%d self=%d",
             evname(e.ev_type), n->tgid, n->comm, n->risk_pct, base,
             (int)gate_sup, (int)gate_en, (int)gate_warm, (int)gate_pend,
             (int)gate_floor, (int)gate_thr, (int)gate_self);
    }
    if (gate_sup && gate_en && gate_warm && gate_pend && gate_floor && gate_thr && gate_self) {
        std::uint32_t pg = n->pgid;
        TLOG("FREEZE-CHK tgid=%u pg=%u own_pgid=%u pass=%d", n->tgid, pg, own_pgid_,
             (int)(pg > 1 && pg != own_pgid_));
        if (pg > 1 && pg != own_pgid_) {
            ::kill(-static_cast<pid_t>(pg), SIGSTOP);
            n->frozen = true;
            n->prompt_pending = true;
            enqueue_prompt(n, ev_action_desc(e.ev_type), false);
            char fm[160];
            std::snprintf(fm, sizeof(fm), "[FREEZE] pid=%u %s suspended at %.0f%% pending decision",
                          n->pid, n->comm, n->risk_pct * 100.0);
            log_alert(fm);
        }
    }
}

void Tracker::mitigate(std::shared_ptr<ProcNode> n) {
    if (!n || n->exempt || n->kill_flagged) return;
    if (node_is_supervised(n)) return;
    if (self_pid(n->pid, n->pgid)) return;
    std::uint32_t pgid = n->pgid;
    if (pgid <= 1) return;
    if (pgid == own_pgid_) return;
    n->kill_flagged = true;
    TLOG("MITIGATE tgid=%u pgid=%u comm='%.16s' risk=%.3f auto_kill=%d",
         n->tgid, pgid, n->comm, n->risk_pct, (int)cfg_.auto_kill_enabled);
    if (cfg_.auto_kill_enabled) {
        if (::kill(-static_cast<pid_t>(pgid), SIGKILL) == 0) {
            kills_.fetch_add(1);
            char msg[192];
            std::snprintf(msg, sizeof(msg),
                "[AUTO-KILL] pgid=%u pid=%u comm=%s risk=%.1f%% EXECUTED",
                pgid, n->pid, n->comm, n->risk_pct * 100.0);
            log_alert(msg);
            n->is_dead = true; n->died_ts = now_sec();
            auto wit = watchlist_.find(n->uid);
            if (wit != watchlist_.end()) wit->second.is_dead = true;
        }
    } else {
        char msg[192];
        std::snprintf(msg, sizeof(msg),
            "[WOULD-KILL] pgid=%u pid=%u comm=%s risk=%.1f%% (auto_kill disabled)",
            pgid, n->pid, n->comm, n->risk_pct * 100.0);
        log_alert(msg);
    }
}

void Tracker::detach_from_parent(const std::shared_ptr<ProcNode> &n) {
    if (!n) return;
    auto p = n->parent.lock();
    if (!p) {
        auto it = std::find(roots_.begin(), roots_.end(), n);
        if (it != roots_.end()) roots_.erase(it);
        return;
    }
    auto &v = p->children;
    v.erase(std::remove(v.begin(), v.end(), n), v.end());
}

void Tracker::gc_sweep(double now_s) {
    std::vector<std::string> to_erase;
    for (auto &kv : nodes_) {
        auto &n = kv.second;
        if (!n || !n->is_dead) continue;
        double keep_metric = std::max(n->peak_risk_pct, n->badge_peak);
        if (keep_metric >= cfg_.gc_forensic_keep) continue;
        double ttl = cfg_.gc_base_ttl_sec + cfg_.gc_peak_ttl_coeff * keep_metric;
        double ddt = now_s - n->died_ts;
        double live = std::max(n->risk_pct, n->badge_risk);
        if (live < cfg_.gc_tomb_risk_floor && ddt > ttl)
            to_erase.push_back(n->uid);
    }
    for (auto &u : to_erase) {
        auto it = nodes_.find(u);
        if (it == nodes_.end()) continue;
        detach_from_parent(it->second);
        std::uint32_t dt = it->second->tgid;
        for (auto pit = pid_to_uid_.begin(); pit != pid_to_uid_.end(); ) {
            if (pit->second == u) pit = pid_to_uid_.erase(pit);
            else ++pit;
        }
        supervised_roots_.erase(dt);
        nodes_.erase(it);
    }
}

void Tracker::tick() {
    double t = now_sec();
    bool warm = (t - start_ts_) >= cfg_.warmup_sec;

    if (burst_epoch_fd_ >= 0 && cfg_.burst_window_ms > 0) {
        double win_s = (double)cfg_.burst_window_ms / 1000.0;
        if ((t - last_epoch_bump_) >= win_s) {
            epoch_++;
            std::uint32_t z = 0;
            bpf_map_update_elem(burst_epoch_fd_, &z, &epoch_, BPF_ANY);
            last_epoch_bump_ = t;
        }
    }

    std::vector<std::shared_ptr<ProcNode>> kill_list;
    {
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        for (auto &kv : nodes_) {
            auto &n = kv.second;
            if (!n || n->exempt || n->frozen) continue;
            decay_to(n, t);
            recompute(n);
        }
        recompute_badges();
        for (auto &kv : nodes_) {
            auto &n = kv.second;
            if (!n || n->exempt || n->frozen) continue;
            if (!n->is_dead) update_watchlist(n);
            if (n->is_dead) continue;
            if (node_is_supervised(n)) { n->above_since = 0.0; continue; }
            if (n->risk_pct >= cfg_.kill_threshold) {
                if (n->above_since <= 0.0) n->above_since = t;
                if (warm && (t - n->above_since) >= cfg_.dwell_sec)
                    kill_list.push_back(n);
            } else {
                n->above_since = 0.0;
            }
        }
        for (auto &n : kill_list) mitigate(n);
        gc_sweep(t);
    }
}

SnapNode Tracker::build_snap(const std::shared_ptr<ProcNode> &n) const {
    SnapNode s;
    s.pid = n->pid;
    s.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
    s.risk_pct = (n->is_dead && !n->exempt) ? n->peak_risk_pct : n->risk_pct;
    s.badge_risk = n->exempt ? 0.0 : ((n->is_dead) ? n->badge_peak : n->badge_risk);
    s.is_dead = n->is_dead;
    s.is_new = n->is_new;
    s.exempt = n->exempt;
    s.frozen = n->frozen;
    s.blocked = n->blocked;
    s.supervised = n->supervised || (bool)supervised_roots_.count(n->tgid);
    for (auto &c : n->children) if (c) s.children.push_back(build_snap(c));
    return s;
}

void Tracker::collect_top(const std::shared_ptr<ProcNode> &n, std::vector<TopEntry> &out) const {
    if (!n) return;
    if (!n->is_dead && !n->exempt && n->risk_pct > 0.01) {
        TopEntry e;
        e.pid = n->pid;
        e.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
        e.risk_pct = n->risk_pct;
        e.origin = compute_origin(n);
        out.push_back(e);
    }
    for (auto &c : n->children) collect_top(c, out);
}

Snapshot Tracker::snapshot() const {
    Snapshot s;
    std::shared_lock<std::shared_mutex> lk(g_lock_);
    for (auto &r : roots_) if (r) s.roots.push_back(build_snap(r));
    std::vector<TopEntry> all;
    for (auto &r : roots_) collect_top(r, all);
    std::sort(all.begin(), all.end(),
        [](const TopEntry &a, const TopEntry &b) { return a.risk_pct > b.risk_pct; });
    if (all.size() > 3) all.resize(3);
    s.top3 = std::move(all);
    s.total_nodes = nodes_.size();
    for (auto &kv : nodes_) {
        if (!kv.second) continue;
        if (!kv.second->is_dead) s.live_nodes++;
        if (kv.second->is_new && !kv.second->is_dead && !kv.second->exempt) s.new_nodes++;
        if (kv.second->frozen) s.frozen_count++;
        if ((kv.second->supervised || supervised_roots_.count(kv.second->tgid)) && !kv.second->is_dead)
            s.supervised_count++;
    }
    std::size_t mn = std::min<std::size_t>(8, masq_events_.size());
    for (std::size_t i = masq_events_.size() - mn; i < masq_events_.size(); i++)
        s.masq_events.push_back(masq_events_[i]);
    for (auto &kv : watchlist_) s.watchlist.push_back(kv.second);
    std::sort(s.watchlist.begin(), s.watchlist.end(),
        [](const WatchEntry &a, const WatchEntry &b) { return a.peak_risk_pct > b.peak_risk_pct; });
    s.watch_count = watchlist_.size();
    return s;
}

std::vector<std::string> Tracker::tail_alerts(std::size_t n) const {
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lk(alert_lock_);
    std::size_t sz = alerts_.size();
    std::size_t start = (sz > n) ? (sz - n) : 0;
    for (std::size_t i = start; i < sz; i++) out.push_back(alerts_[i]);
    return out;
}

void Tracker::push_alert(const std::string &s) { log_alert(s); }
void Tracker::stop() { running_.store(false); }

int Tracker::reputation_verdict(std::uint32_t tgid, std::string &hash_out,
                                std::string &path_out) {
    if (!rep_) return 0;
    auto hit = tgid_hash_.find(tgid);
    if (hit == tgid_hash_.end() || hit->second.empty()) return 0;
    hash_out = hit->second;
    auto pit = tgid_path_.find(tgid);
    if (pit != tgid_path_.end()) path_out = pit->second;
    if (rep_->is_whitelisted(hash_out)) return -1;
    if (rep_->is_blacklisted(hash_out)) return 1;
    return 0;
}

void Tracker::mark_dead(std::uint32_t tgid) {
    if (tgid == 0) return;
    std::unique_lock<std::shared_mutex> lk(g_lock_);
    auto n = lookup_by_pid(tgid);
    if (!n) return;
    n->is_dead = true;
    n->died_ts = now_sec();
    n->frozen = false;
    n->supervised = false;
    auto wit = watchlist_.find(n->uid);
    if (wit != watchlist_.end()) wit->second.is_dead = true;
    if (n->blocked) { n->blocked = false; disarm_block(n->tgid); }
    kernel_exempt(n->tgid, false);
    supervised_roots_.erase(n->tgid);
}

std::size_t Tracker::purge_dead(bool force) {
    std::unique_lock<std::shared_mutex> lk(g_lock_);
    std::vector<std::string> to_erase;
    for (auto &kv : nodes_) {
        auto &n = kv.second;
        if (!n || !n->is_dead) continue;

        bool has_live_child = false;
        for (auto &c : n->children) {
            if (c && !c->is_dead) { has_live_child = true; break; }
        }
        if (has_live_child) continue;

        if (!force) {
            double keep = std::max(n->peak_risk_pct, n->badge_peak);
            if (keep >= cfg_.gc_forensic_keep) continue;
        }
        to_erase.push_back(n->uid);
    }
    for (auto &u : to_erase) {
        auto it = nodes_.find(u);
        if (it == nodes_.end()) continue;
        detach_from_parent(it->second);
        std::uint32_t dt = it->second->tgid;
        for (auto pit = pid_to_uid_.begin(); pit != pid_to_uid_.end(); ) {
            if (pit->second == u) pit = pid_to_uid_.erase(pit);
            else ++pit;
        }
        watchlist_.erase(u);
        tgid_hash_.erase(dt);
        supervised_roots_.erase(dt);
        nodes_.erase(it);
    }
    char m[96];
    std::snprintf(m, sizeof(m), "[GC] purged %zu dead node(s)%s",
                  to_erase.size(), force ? " (forced, incl. forensic)" : "");
    log_alert(m);
    return to_erase.size();
}

std::size_t Tracker::kill_supervised_tree(std::uint32_t root_tgid) {
    std::vector<std::uint32_t> victims;
    {
        std::shared_lock<std::shared_mutex> lk(g_lock_);
        auto root = lookup_by_pid(root_tgid);
        if (!root) return 0;
        std::vector<std::shared_ptr<ProcNode>> stack{ root };
        int guard = 0;
        while (!stack.empty() && guard++ < 8192) {
            auto cur = stack.back();
            stack.pop_back();
            if (!cur || cur->is_dead) continue;
            if (cur->tgid > 1) victims.push_back(cur->tgid);
            for (auto &c : cur->children) stack.push_back(c);
        }
    }
    std::size_t n = 0;
    for (auto tg : victims) {
        if (::kill((pid_t)tg, SIGKILL) == 0) n++;
    }
    char m[96];
    std::snprintf(m, sizeof(m), "[SECCOMP] killed supervised tree: %zu process(es)", n);
    log_alert(m);
    return n;
}
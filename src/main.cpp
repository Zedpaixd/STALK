#include "common.h"
#include "hasher.h"
#include "math_engine.h"
#include "reputation.h"
#include "tracker.h"
#include "keymap.h"
#include "seccomp_supervisor.h"
#include "ui.h"
#include "edr.skel.h"
#include <bpf/libbpf.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <memory>
#include <signal.h>
#include <string>
#include <sys/resource.h>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <vector>

static std::atomic<bool> g_run{true};
static Tracker *g_tr = nullptr;

static void on_sig(int) { g_run.store(false); if (g_tr) g_tr->stop(); }

static int libbpf_verbose(enum libbpf_print_level lvl, const char *fmt, va_list ap) {
    (void)lvl;
    return vfprintf(stderr, fmt, ap);
}

static int rb_cb(void *ctx, void *data, std::size_t sz) {
    if (sz < sizeof(edr_event)) return 0;
    auto *tr = static_cast<Tracker *>(ctx);
    tr->ingest(*static_cast<const edr_event *>(data));
    return 0;
}

static void try_attach(bpf_program *p, Tracker *tr, const char *nm) {
    if (!p) { tr->note_hook_fail(); tr->push_alert(std::string("[hook] missing prog: ") + nm); return; }
    errno = 0;
    struct bpf_link *lk = bpf_program__attach(p);
    if (!lk) {
        int e = errno; tr->note_hook_fail();
        char msg[256];
        std::snprintf(msg, sizeof(msg), "[hook] FAIL %s (errno=%d %s)", nm, e, std::strerror(e));
        tr->push_alert(msg);
    } else tr->push_alert(std::string("[hook] attached: ") + nm);
}

static void bump_rlim() {
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &r);
}

static char tty_key() {
    int fd = ::open("/dev/tty", O_RDONLY);
    if (fd < 0) fd = STDIN_FILENO;
    struct termios old, raw;
    tcgetattr(fd, &old);
    raw = old; raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
    tcsetattr(fd, TCSANOW, &raw);
    char c = 0; ssize_t n = read(fd, &c, 1);
    tcsetattr(fd, TCSANOW, &old);
    if (fd != STDIN_FILENO) ::close(fd);
    return n <= 0 ? 0 : c;
}

struct BindIssue { std::string text; };

static std::vector<BindIssue> validate_binds(const Keymap &km) {
    std::vector<BindIssue> issues;

    struct Ctx { const char *name; std::vector<KmAction> acts; };
    std::vector<Ctx> ctxs = {
        { "dashboard", { KM_QUIT, KM_REPMAN, KM_KEYPANE, KM_LAUNCH, KM_PAUSE, KM_ENFORCE,
                         KM_CLEAR, KM_NEWONLY, KM_ALL, KM_RESET_H, KM_SEL_UP, KM_SEL_DOWN,
                         KM_SEL_TOP, KM_SEL_BOTTOM } },
        { "eBPF modal", { KM_ALLOW, KM_DENY, KM_BLOCK, KM_KILL, KM_BLACKLIST, KM_WHITELIST, KM_SESSION_WL } },
        { "seccomp modal", { KM_ALLOW, KM_DENY, KM_KILL, KM_BLACKLIST, KM_WHITELIST } },
        { "reputation manager", { KM_REP_PAUSE, KM_REP_REMOVE, KM_SEL_UP, KM_SEL_DOWN, KM_SEL_TOP, KM_SEL_BOTTOM } },
    };

    for (int a = 0; a < KM_COUNT; a++) {
        if (km.key_for((KmAction)a).empty())
            issues.push_back({ std::string("action index ") + std::to_string(a) + " is not mapped" });
        if (km.key_for((KmAction)a) == "esc")
            issues.push_back({ "an action is bound to 'esc', which is reserved for cancel and cannot be rebound" });
    }

    for (auto &cx : ctxs) {
        for (std::size_t i = 0; i < cx.acts.size(); i++) {
            for (std::size_t j = i + 1; j < cx.acts.size(); j++) {
                std::string ki = km.key_for(cx.acts[i]);
                std::string kj = km.key_for(cx.acts[j]);
                if (!ki.empty() && ki == kj) {
                    issues.push_back({ std::string("in ") + cx.name + ": two actions share key '" + ki + "'" });
                }
            }
        }
    }
    return issues;
}

int main(int argc, char **argv) {
    if (geteuid() != 0) { std::fprintf(stderr, "must run as root\n"); return 1; }
    const char *cfg_path = (argc > 1) ? argv[1] : "rules.json";
    auto cfg_opt = MathEng::load(cfg_path);
    if (!cfg_opt) { std::fprintf(stderr, "failed to load %s\n", cfg_path); return 1; }
    Keymap km;
    std::string km_note;
    km.load("binds.json", km_note);
    auto issues = validate_binds(km);
    if (!issues.empty()) {
        std::printf("\n=== binds.json validation ===\n");
        std::printf("%s\n", km_note.c_str());
        std::printf("Problems found:\n");
        for (auto &is : issues) std::printf("  - %s\n", is.text.c_str());
        std::printf("\n[d] discard binds.json and use built-in defaults\n");
        std::printf("[q] quit so you can fix binds.json\n");
        std::printf("choose (d/q): ");
        std::fflush(stdout);
        for (;;) {
            char c = tty_key();
            if (c == 'd' || c == 'D') {
                std::printf("d\nusing default keybinds.\n\n");
                Keymap def;
                km = def;
                break;
            }
            if (c == 'q' || c == 'Q' || c == 3) {
                std::printf("q\nexiting so you can fix binds.json.\n");
                return 0;
            }
        }
    }
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    libbpf_set_print(libbpf_verbose);
    bump_rlim();
    auto rep = std::make_shared<Reputation>(cfg_opt->reputation_path);
    rep->load();
    std::uint32_t opgid = static_cast<std::uint32_t>(getpgid(0));
    std::uint32_t opid  = static_cast<std::uint32_t>(getpid());
    std::fprintf(stderr, "[SELF] pid=%u pgid=%u\n", opid, opgid);
    auto tr = std::make_shared<Tracker>(*cfg_opt, opgid, opid, rep);
    auto hasher = std::make_shared<BinHasher>(2, 8192);
    tr->attach_hasher(hasher);
    hasher->set_callback([w = std::weak_ptr<Tracker>(tr)](const FileId &id,
                                                          const std::string &h,
                                                          const std::string &p) {
        if (auto t = w.lock()) t->on_hash_ready(id, h, p);
    });
    g_tr = tr.get();
    auto sup = std::make_shared<SeccompSupervisor>();
    sup->attach_tracker(tr.get());
    if (rep->tamper_flagged())
        tr->push_alert("[REP] WARNING reputation store checksum mismatch - possible tampering");
    {
        char m[128];
        std::snprintf(m, sizeof(m), "[REP] loaded %zu saved binary verdicts from %s",
                      rep->count(), rep->store_path().c_str());
        tr->push_alert(m);
    }
    tr->push_alert(std::string("[keys] ") + km_note);
    if (access("/sys/kernel/tracing/events/sched/sched_process_fork/id", F_OK) != 0) {
        std::fprintf(stderr, "tracefs not mounted. run: sudo mount -t tracefs nodev /sys/kernel/tracing\n");
        return 1;
    }
    struct stat pns;
    if (::stat("/proc/self/ns/pid", &pns) != 0) {
        std::fprintf(stderr, "cannot stat /proc/self/ns/pid (errno=%d %s)\n",
                     errno, std::strerror(errno));
        return 1;
    }
    std::fprintf(stderr, "[SELF] pidns dev=%llu ino=%llu\n",
                 (unsigned long long)pns.st_dev, (unsigned long long)pns.st_ino);
    struct edr_bpf *sk = edr_bpf__open();
    if (!sk) { std::fprintf(stderr, "skel open fail\n"); return 1; }
    auto fp = [](double d) -> std::uint32_t { return (std::uint32_t)(d * (double)BURST_FP_SCALE); };
    sk->rodata->deny_exec         = cfg_opt->deny_exec ? 1 : 0;
    sk->rodata->deny_wx           = cfg_opt->deny_wx ? 1 : 0;
    sk->rodata->deny_setuid       = cfg_opt->deny_setuid ? 1 : 0;
    sk->rodata->deny_ptrace       = cfg_opt->deny_ptrace ? 1 : 0;
    sk->rodata->deny_connect      = cfg_opt->deny_connect ? 1 : 0;
    sk->rodata->block_descendants = cfg_opt->block_descendants ? 1 : 0;
    sk->rodata->emit_deny_events  = cfg_opt->emit_deny_events ? 1 : 0;
    sk->rodata->self_tgid         = opid;
    sk->rodata->pidns_dev         = (std::uint64_t)pns.st_dev;
    sk->rodata->pidns_ino         = (std::uint64_t)pns.st_ino;
    sk->rodata->burst_enabled     = cfg_opt->burst_enabled ? 1 : 0;
    sk->rodata->burst_ceiling_fp  = (std::uint64_t)(cfg_opt->burst_ceiling * (double)BURST_FP_SCALE);
    sk->rodata->bw_memfd          = fp(cfg_opt->bw_memfd);
    sk->rodata->bw_wx             = fp(cfg_opt->bw_wx);
    sk->rodata->bw_ptrace         = fp(cfg_opt->bw_ptrace);
    sk->rodata->bw_creds          = fp(cfg_opt->bw_creds);
    sk->rodata->bw_unshare        = fp(cfg_opt->bw_unshare);
    sk->rodata->bw_rename         = fp(cfg_opt->bw_rename);
    sk->rodata->bw_secbpf         = fp(cfg_opt->bw_secbpf);
    sk->rodata->bw_connect        = fp(cfg_opt->bw_connect);
    sk->rodata->bw_exec           = fp(cfg_opt->bw_exec);
    if (edr_bpf__load(sk)) {
        std::fprintf(stderr, "skel load fail (errno=%d %s)\n", errno, std::strerror(errno));
        edr_bpf__destroy(sk);
        return 1;
    }
    try_attach(sk->progs.tp_fork, tr.get(), "sched_process_fork");
    try_attach(sk->progs.tp_exit, tr.get(), "sched_process_exit");
    try_attach(sk->progs.tp_execve, tr.get(), "sys_enter_execve");
    try_attach(sk->progs.tp_execveat, tr.get(), "sys_enter_execveat");
    try_attach(sk->progs.tp_prctl, tr.get(), "sys_enter_prctl");
    try_attach(sk->progs.tp_ptrace, tr.get(), "sys_enter_ptrace");
    try_attach(sk->progs.tp_unshare, tr.get(), "sys_enter_unshare");
    try_attach(sk->progs.tp_mprotect, tr.get(), "sys_enter_mprotect");
    try_attach(sk->progs.krp_memfd, tr.get(), "kretprobe/memfd_create");
    try_attach(sk->progs.kp_commit_creds, tr.get(), "kprobe/commit_creds");
    try_attach(sk->progs.kp_sec_bpf, tr.get(), "kprobe/security_bpf");
    try_attach(sk->progs.kp_tcp_conn, tr.get(), "kprobe/tcp_v4_connect");
    try_attach(sk->progs.lsm_bprm, tr.get(), "lsm/bprm_check_security");
    try_attach(sk->progs.lsm_mprotect, tr.get(), "lsm/file_mprotect");
    try_attach(sk->progs.lsm_mmap, tr.get(), "lsm/mmap_file");
    try_attach(sk->progs.lsm_setuid, tr.get(), "lsm/task_fix_setuid");
    try_attach(sk->progs.lsm_ptrace, tr.get(), "lsm/ptrace_access_check");
    try_attach(sk->progs.lsm_connect, tr.get(), "lsm/socket_connect");
    try_attach(sk->progs.tp_exec_done, tr.get(), "sched_process_exec");
    tr->set_enforcement_fds(bpf_map__fd(sk->maps.blocked_tgids), bpf_map__fd(sk->maps.enforce_on));
    tr->set_burst_fds(bpf_map__fd(sk->maps.burst_epoch), bpf_map__fd(sk->maps.exempt_tgids));
    tr->set_enforcement(cfg_opt->enforce_enabled);
    tr->seed_from_proc();
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(sk->maps.rb), rb_cb, tr.get(), nullptr);
    if (!rb) { std::fprintf(stderr, "ringbuf init failed\n"); edr_bpf__destroy(sk); return 1; }
    std::thread poller([&]() {
        while (g_run.load() && tr->running()) {
            int r = ring_buffer__poll(rb, 100);
            if (r < 0 && r != -EINTR) break;
            if (r == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });
    std::thread engine([&]() {
        auto ms = std::chrono::milliseconds(cfg_opt->tick_ms);
        while (g_run.load() && tr->running()) { tr->tick(); std::this_thread::sleep_for(ms); }
    });
    Ui ui(tr, sup, km);
    ui.run();
    g_run.store(false);
    tr->stop();
    sup->stop();
    if (poller.joinable()) poller.join();
    if (engine.joinable()) engine.join();
    ring_buffer__free(rb);
    edr_bpf__destroy(sk);
    hasher->stop();
    return 0;
}
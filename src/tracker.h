#ifndef EDR_TRACKER_H
#define EDR_TRACKER_H

#include "common.h"
#include "math_engine.h"
#include "hasher.h"
#include "reputation.h"
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct ProcNode {
    std::string uid;
    std::uint32_t pid = 0;
    std::uint32_t tgid = 0;
    std::uint32_t ppid = 0;
    std::uint32_t pgid = 0;
    std::uint32_t owner_uid = 0;
    std::uint32_t ns_inum = 0;
    char comm[MAX_COMM] = {0};
    double cat_accum[CAT_COUNT] = {0};
    double logodds = 0.0;
    double risk_pct = 0.0;
    double peak_risk_pct = 0.0;
    double badge_risk = 0.0;
    double badge_peak = 0.0;
    double last_score_ts = 0.0;
    double last_ev_ts = 0.0;
    double created_ts = 0.0;
    double died_ts = 0.0;
    double above_since = 0.0;
    bool   is_dead = false;
    bool   is_new = false;
    bool   exempt = false;
    bool   kill_flagged = false;
    bool   frozen = false;
    bool   prompt_pending = false;
    bool   blocked = false;
    bool   rep_checked = false;
    bool   supervised = false;
    std::weak_ptr<ProcNode> parent;
    std::vector<std::shared_ptr<ProcNode>> children;
    std::string cached_hash;
    std::string cached_path;
    FileId fid;
};

struct SnapNode {
    std::uint32_t pid = 0;
    std::string   comm;
    double        risk_pct = 0.0;
    double        badge_risk = 0.0;
    bool          is_dead = false;
    bool          is_new = false;
    bool          exempt = false;
    bool          frozen = false;
    bool          blocked = false;
    bool          supervised = false;
    std::vector<SnapNode> children;
};

struct TopEntry {
    std::uint32_t pid = 0;
    std::string   comm;
    double        risk_pct = 0.0;
    std::string   origin;
};

struct MasqEvent {
    std::string   tstr;
    std::uint32_t pid = 0;
    std::string   old_comm;
    std::string   new_comm;
    double        risk_pct = 0.0;
    bool          suspicious = false;
};

struct WatchEntry {
    std::string   uid;
    std::string   first_tstr;
    std::string   origin;
    std::uint32_t pid = 0;
    std::string   comm;
    std::string   stages;
    double        peak_risk_pct = 0.0;
    double        current_risk_pct = 0.0;
    std::size_t   child_count = 0;
    bool          is_dead = false;
};

struct PromptReq {
    std::string   uid;
    std::uint32_t pid = 0;
    std::uint32_t pgid = 0;
    std::string   comm;
    std::string   origin;
    std::string   doing;
    double        risk = 0.0;
    std::string hash;
    std::string path;
    bool identity_ready = false;
    std::string   allow_lbl;
    std::string   deny_lbl;
    std::string   kill_lbl;
    std::string   wl_lbl;
    bool          from_burst = false;
};

struct Snapshot {
    std::vector<SnapNode>   roots;
    std::vector<TopEntry>   top3;
    std::vector<MasqEvent>  masq_events;
    std::vector<WatchEntry> watchlist;
    std::size_t total_nodes = 0;
    std::size_t live_nodes = 0;
    std::size_t new_nodes = 0;
    std::size_t watch_count = 0;
    std::size_t frozen_count = 0;
    std::size_t supervised_count = 0;
};

struct RiskPrediction {
    bool known = false;
    bool scores = false;
    double current = -1.0;
    double predicted = -1.0;
    std::string comm;
    std::string exe_path;
    bool has_parent = false;
    double parent_current = -1.0;
    double parent_predicted = -1.0;
    std::string parent_comm;
};

struct SessionEntry {
    std::string key;
    std::string name;
    std::string path;
    std::string added_tstr;
    bool paused = false;
};

class Tracker {
public:
    Tracker(EngineCfg cfg, std::uint32_t own_pgid, std::uint32_t own_pid,
            std::shared_ptr<Reputation> rep);
    std::vector<SessionEntry> session_list() const;
    bool session_set_paused(const std::string &key, bool paused);
    bool session_remove(const std::string &key);
    void attach_hasher(std::shared_ptr<BinHasher> h) { hasher_ = std::move(h); }
    void on_hash_ready(const FileId &id, const std::string &hash, const std::string &path);
    void seed_from_proc();
    void ingest(const edr_event &e);
    void tick();
    Snapshot snapshot() const;
    std::vector<std::string> tail_alerts(std::size_t n) const;
    void push_alert(const std::string &s);
    void stop();
    bool running() const { return running_.load(); }
    std::uint64_t kills_issued() const { return kills_.load(); }
    std::uint64_t hooks_failed() const { return hook_fails_.load(); }
    void note_hook_fail() { hook_fails_.fetch_add(1); }
    std::uint64_t ev_count() const { return ev_count_.load(); }
    double warmup_remaining() const;
    bool prompts_enabled() const { return cfg_.prompt_enabled; }
    std::optional<PromptReq> take_prompt();
    void resolve_prompt(const std::string &uid, std::uint32_t pgid, char decision);
    void set_enforcement_fds(int block_fd, int switch_fd);
    void set_burst_fds(int epoch_fd, int exempt_fd);
    void set_enforcement(bool on);
    void flush_blocks();
    bool enforcement_on() const { return enforce_on_.load(); }
    std::uint64_t denies() const { return denies_.load(); }
    std::uint64_t burst_trips() const { return burst_trips_.load(); }
    std::uint64_t rep_blocks() const { return rep_blocks_.load(); }
    std::size_t blocks_active() const;
    std::shared_ptr<Reputation> reputation() const { return rep_; }
    void reblock_from_reputation(const std::string &hash);
    void unblock_hash_live(const std::string &hash);

    void register_supervised(std::uint32_t tgid);
    void unregister_supervised(std::uint32_t tgid);
    RiskPrediction predict_for_syscall(std::uint32_t tgid, int syscall_nr,
                                       std::uint64_t a0, std::uint64_t a1, std::uint64_t a2);
    void commit_syscall_evidence(std::uint32_t tgid, int syscall_nr,
                                 std::uint64_t a0, std::uint64_t a2);
    void seccomp_persist_hash(std::uint32_t tgid, bool blacklist);
    void mark_dead(std::uint32_t tgid);
    std::size_t purge_dead(bool force);
    std::size_t kill_supervised_tree(std::uint32_t root_tgid);

private:
    std::unordered_map<std::string, SessionEntry> session_allow_;
    bool session_allowed(const FileId &id) const;
    void recompute_exempt(const std::shared_ptr<ProcNode> &n);
    void apply_session_locked(const std::string &key);
    std::shared_ptr<BinHasher> hasher_;
    std::unordered_map<std::uint32_t, FileId> tgid_fid_;
    void prime_identity(const edr_event &e);
    EngineCfg cfg_;
    std::uint32_t own_pgid_;
    std::uint32_t own_pid_;
    std::shared_ptr<Reputation> rep_;
    double start_ts_ = 0.0;
    mutable std::shared_mutex g_lock_;
    std::unordered_map<std::string, std::shared_ptr<ProcNode>> nodes_;
    std::unordered_map<std::uint32_t, std::string> pid_to_uid_;
    std::unordered_map<std::uint32_t, std::string> tgid_hash_;
    std::unordered_map<std::uint32_t, std::string> tgid_path_;
    std::unordered_set<std::uint32_t> supervised_roots_;
    std::vector<std::shared_ptr<ProcNode>> roots_;
    std::deque<MasqEvent> masq_events_;
    std::unordered_map<std::string, WatchEntry> watchlist_;
    mutable std::mutex alert_lock_;
    std::deque<std::string> alerts_;
    std::mutex prompt_mtx_;
    std::deque<PromptReq> prompt_q_;
    std::atomic<bool> running_{true};
    std::atomic<std::uint64_t> kills_{0};
    std::atomic<std::uint64_t> hook_fails_{0};
    std::atomic<std::uint64_t> ev_count_{0};
    int block_map_fd_ = -1;
    int enforce_switch_fd_ = -1;
    int burst_epoch_fd_ = -1;
    int exempt_fd_ = -1;
    double last_epoch_bump_ = 0.0;
    std::uint32_t epoch_ = 0;
    std::atomic<bool> enforce_on_{true};
    std::atomic<std::uint64_t> denies_{0};
    std::atomic<std::uint64_t> burst_trips_{0};
    std::atomic<std::uint64_t> rep_blocks_{0};
    void inherit_identity(std::uint32_t child_tgid, std::uint32_t parent_tgid);
    std::string mk_uid(std::uint32_t tgid, std::uint64_t ts_ns) const;
    std::shared_ptr<ProcNode> lookup_by_pid(std::uint32_t tgid);
    std::shared_ptr<ProcNode> ensure_node(const edr_event &e);
    std::shared_ptr<ProcNode> fork_node(const edr_event &e);
    std::shared_ptr<ProcNode> synth_node(std::uint32_t tgid, bool supervised);
    std::string ev_key(std::uint8_t t) const;
    bool self_pid(std::uint32_t pid, std::uint32_t pgid) const;
    bool is_self(const edr_event &e) const;
    bool is_exempt_comm(const char *nm) const;
    bool is_masq_name(const char *nm) const;
    bool node_is_supervised(const std::shared_ptr<ProcNode> &n) const;
    double ctx_mult(const edr_event &e, const std::shared_ptr<ProcNode> &n) const;
    void decay_to(const std::shared_ptr<ProcNode> &n, double now);
    void recompute(const std::shared_ptr<ProcNode> &n);
    void add_evidence(const std::shared_ptr<ProcNode> &n, int cat, double amount, double now);
    void backprop(const std::shared_ptr<ProcNode> &n, int cat, double amount, int depth, double now);
    std::shared_ptr<ProcNode> responsible_launcher(const std::shared_ptr<ProcNode> &src);
    void recompute_badges();
    std::string active_stages(const std::shared_ptr<ProcNode> &n) const;
    std::string compute_origin(const std::shared_ptr<ProcNode> &n) const;
    void enqueue_prompt(const std::shared_ptr<ProcNode> &n, const std::string &action, bool burst);
    void update_watchlist(const std::shared_ptr<ProcNode> &n);
    void log_masquerade(const std::shared_ptr<ProcNode> &n, const char *new_name, bool susp);
    void log_alert(const std::string &s);
    SnapNode build_snap(const std::shared_ptr<ProcNode> &n) const;
    void collect_top(const std::shared_ptr<ProcNode> &n, std::vector<TopEntry> &out) const;
    void gc_sweep(double now_sec);
    void mitigate(std::shared_ptr<ProcNode> n);
    void detach_from_parent(const std::shared_ptr<ProcNode> &n);
    bool arm_block(std::uint32_t tgid);
    void disarm_block(std::uint32_t tgid);
    void kernel_exempt(std::uint32_t tgid, bool on);
    void remember_exec(std::uint32_t tgid, const std::string &path, const std::string &hash);
    int reputation_verdict(std::uint32_t tgid, std::string &hash_out, std::string &path_out);
    int syscall_to_evtype(int nr, std::uint64_t a0, std::uint64_t a2) const;
};

#endif
#define EDR_BPF_SIDE
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#define PR_SET_NAME 15
#define AF_INET 2
#define AF_INET6 10

#ifndef EPERM
#define EPERM 1
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct exec_ctx);
} exec_state SEC(".maps");

struct str_scratch { char buf[MAX_ARG_LEN]; };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct str_scratch);
} str_buf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct blk_val);
} blocked_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} enforce_on SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct burst_val);
} burst_win SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} burst_epoch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} exempt_tgids SEC(".maps");

volatile const __u8  deny_exec         = 1;
volatile const __u8  deny_wx           = 1;
volatile const __u8  deny_setuid       = 1;
volatile const __u8  deny_ptrace       = 1;
volatile const __u8  deny_connect      = 1;
volatile const __u8  block_descendants = 1;
volatile const __u8  emit_deny_events  = 1;
volatile const __u32 self_tgid         = 0;
volatile const __u64 pidns_dev = 0;
volatile const __u64 pidns_ino = 0;

volatile const __u8  burst_enabled     = 1;
volatile const __u64 burst_ceiling_fp  = 983040;
volatile const __u32 bw_memfd          = 131072;
volatile const __u32 bw_wx             = 163840;
volatile const __u32 bw_ptrace         = 163840;
volatile const __u32 bw_creds          = 196608;
volatile const __u32 bw_unshare        = 98304;
volatile const __u32 bw_rename         = 0;
volatile const __u32 bw_secbpf         = 98304;
volatile const __u32 bw_connect        = 65536;
volatile const __u32 bw_exec           = 0;

static __always_inline __u32 rd_pgid(struct task_struct *t) {
    if (!t) return 0;
    struct signal_struct *s = BPF_CORE_READ(t, signal);
    if (!s) return 0;
    struct pid *pp = BPF_CORE_READ(s, pids[PIDTYPE_PGID]);
    if (!pp) return 0;
    return BPF_CORE_READ(pp, numbers[0].nr);
}

static __always_inline __u32 rd_nsinum(struct task_struct *t) {
    if (!t) return 0;
    struct nsproxy *n = BPF_CORE_READ(t, nsproxy);
    if (!n) return 0;
    return BPF_CORE_READ(n, mnt_ns, ns.inum);
}

static __always_inline __u32 rd_ppid(struct task_struct *t) {
    if (!t) return 0;
    return BPF_CORE_READ(t, real_parent, tgid);
}

static __always_inline int cur_ns_ids(__u32 *pid, __u32 *tgid) {
    struct bpf_pidns_info ns = {};
    if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)) != 0)
        return -1;
    *pid = ns.pid;
    *tgid = ns.tgid;
    return 0;
}

static __always_inline __u32 ns_nr_of(struct pid *p) {
    if (!p) return 0;
    unsigned int lvl = BPF_CORE_READ(p, level);
    if (lvl > 8) return 0;
    struct upid up = {};
    if (bpf_probe_read_kernel(&up, sizeof(up), &p->numbers[lvl]) != 0) return 0;
    return up.nr;
}

static __always_inline __u32 ns_tgid_of(struct task_struct *t) {
    if (!t) return 0;
    return ns_nr_of(BPF_CORE_READ(t, signal, pids[PIDTYPE_TGID]));
}

static __always_inline int in_self_tree(void) {
    __u32 pid = 0, tgid = 0;
    if (cur_ns_ids(&pid, &tgid) != 0) return 0;
    if (tgid == self_tgid) return 1;
    struct task_struct *t = bpf_get_current_task_btf();
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (!t) break;
        t = BPF_CORE_READ(t, real_parent);
        if (!t) break;
        __u32 ptg = ns_tgid_of(t);
        if (ptg == 0 || ptg == 1) break;
        if (ptg == self_tgid) return 1;
    }
    return 0;
}

static __always_inline void fill_meta(struct edr_event *e) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    __u64 pt = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (__u32)pt;
    e->tgid = (__u32)(pt >> 32);
    e->ppid = rd_ppid(t);
    e->pgid = rd_pgid(t);
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->ns_inum = rd_nsinum(t);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    if (e->comm[0] == 'e' && e->comm[1] == 'd' && e->comm[2] == 'r' && e->comm[3] == 0) {
        struct task_struct *rp = BPF_CORE_READ(t, real_parent);
        __u32 rp_tgid = rp ? BPF_CORE_READ(rp, tgid) : 0;
        char pcomm[16] = {};
        if (rp) bpf_probe_read_kernel_str(pcomm, sizeof(pcomm), BPF_CORE_READ(rp, comm));
        struct task_struct *gp = rp ? BPF_CORE_READ(rp, real_parent) : 0;
        __u32 gp_tgid = gp ? BPF_CORE_READ(gp, tgid) : 0;
        char gcomm[16] = {};
        if (gp) bpf_probe_read_kernel_str(gcomm, sizeof(gcomm), BPF_CORE_READ(gp, comm));
        bpf_printk("MP pid=%u tgid=%u self=%u", e->pid, e->tgid, self_tgid);
        bpf_printk("MP par=%u '%s'", rp_tgid, pcomm);
        bpf_printk("MP gpar=%u '%s'", gp_tgid, gcomm);
    }
}

static __always_inline struct edr_event *ev_reserve(__u8 ty) {
    struct edr_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->ev_type = ty;
    return e;
}

static __always_inline __u32 cur_epoch(void) {
    __u32 z = 0;
    __u32 *e = bpf_map_lookup_elem(&burst_epoch, &z);
    return e ? *e : 0;
}

static __always_inline void burst_add(__u32 w_fp) {
    if (!burst_enabled || w_fp == 0) return;
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pt >> 32);
    if (tgid <= 1) return;
    if (in_self_tree()) return;
    if (bpf_map_lookup_elem(&exempt_tgids, &tgid)) return;
    __u32 ep = cur_epoch();
    __u64 sum;
    struct burst_val *v = bpf_map_lookup_elem(&burst_win, &tgid);
    if (v) {
        if (v->epoch != ep) { v->sum_fp = 0; v->epoch = ep; }
        v->sum_fp += w_fp;
        sum = v->sum_fp;
    } else {
        struct burst_val nv = {};
        nv.sum_fp = w_fp;
        nv.epoch = ep;
        bpf_map_update_elem(&burst_win, &tgid, &nv, BPF_ANY);
        sum = w_fp;
    }
    if (sum >= burst_ceiling_fp && !bpf_map_lookup_elem(&blocked_tgids, &tgid)) {
        struct blk_val bv = {};
        bv.armed_ns = bpf_ktime_get_ns();
        bv.mode = 1;
        bpf_map_update_elem(&blocked_tgids, &tgid, &bv, BPF_ANY);
        struct edr_event *e = ev_reserve(EV_BURST_TRIP);
        if (e) {
            fill_meta(e);
            e->data.burst.weight_fp = (sum > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : (__u32)sum;
            bpf_ringbuf_submit(e, 0);
        }
    }
}

SEC("tracepoint/sched/sched_process_fork")
int tp_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct edr_event *e = ev_reserve(EV_FORK);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = ctx->child_pid;
    e->tgid = ctx->child_pid;
    e->ppid = ctx->parent_pid;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e->pgid = rd_pgid(t);
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->ns_inum = rd_nsinum(t);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (e->comm[0] == 'e' && e->comm[1] == 'd' && e->comm[2] == 'r' && e->comm[3] == 0) {
        __u64 pt = bpf_get_current_pid_tgid();
        bpf_printk("FORK cur_pid=%u cur_tgid=%u", (__u32)pt, (__u32)(pt >> 32));
        bpf_printk("FORK ctx_parent=%u ctx_child=%u self=%u",
                   ctx->parent_pid, ctx->child_pid, self_tgid);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tp_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pt;
    __u32 tgid = (__u32)(pt >> 32);
    if (pid != tgid) return 0;
    struct edr_event *e = ev_reserve(EV_EXIT);
    if (!e) return 0;
    fill_meta(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline void grab_argv(const char *const *argv, char *dst) {
    const char *p = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (bpf_probe_read_user(&p, sizeof(p), &argv[i]) != 0) return;
        if (!p) return;
        long n = bpf_probe_read_user_str(&dst[i * 64], 63, p);
        if (n <= 0) return;
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 k = 0;
    struct str_scratch *s = bpf_map_lookup_elem(&str_buf, &k);
    if (!s) return 0;
    __builtin_memset(s->buf, 0, MAX_ARG_LEN);
    grab_argv((const char *const *)ctx->args[1], s->buf);
    burst_add(bw_exec);
    struct edr_event *e = ev_reserve(EV_EXEC);
    if (!e) return 0;
    fill_meta(e);
    __builtin_memcpy(e->data.exec.argbuf, s->buf, MAX_ARG_LEN);
    bpf_probe_read_user_str(e->data.exec.filename, MAX_PATH_LEN,
                            (const char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_execveat(struct trace_event_raw_sys_enter *ctx) {
    __u32 k = 0;
    struct str_scratch *s = bpf_map_lookup_elem(&str_buf, &k);
    if (!s) return 0;
    __builtin_memset(s->buf, 0, MAX_ARG_LEN);
    grab_argv((const char *const *)ctx->args[2], s->buf);
    burst_add(bw_exec);
    struct edr_event *e = ev_reserve(EV_EXEC);
    if (!e) return 0;
    fill_meta(e);
    __builtin_memcpy(e->data.exec.argbuf, s->buf, MAX_ARG_LEN);
    bpf_probe_read_user_str(e->data.exec.filename, MAX_PATH_LEN,
                            (const char *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int tp_prctl(struct trace_event_raw_sys_enter *ctx) {
    __u32 op = (__u32)ctx->args[0];
    if (op != PR_SET_NAME) return 0;
    const char *nm = (const char *)ctx->args[1];
    burst_add(bw_rename);
    struct edr_event *e = ev_reserve(EV_PRCTL_RENAME);
    if (!e) return 0;
    fill_meta(e);
    bpf_probe_read_user_str(e->data.rename.new_name, MAX_COMM, nm);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_ptrace(struct trace_event_raw_sys_enter *ctx) {
    burst_add(bw_ptrace);
    struct edr_event *e = ev_reserve(EV_PTRACE);
    if (!e) return 0;
    fill_meta(e);
    e->data.ptrace_ev.req = (__u32)ctx->args[0];
    e->data.ptrace_ev.tgt_pid = (__u32)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int tp_unshare(struct trace_event_raw_sys_enter *ctx) {
    burst_add(bw_unshare);
    struct edr_event *e = ev_reserve(EV_UNSHARE);
    if (!e) return 0;
    fill_meta(e);
    e->data.unshare_ev.flags = (__u32)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int tp_mprotect(struct trace_event_raw_sys_enter *ctx) {
    __u32 prot = (__u32)ctx->args[2];
    if (!((prot & 0x2) && (prot & 0x4))) return 0;
    burst_add(bw_wx);
    struct edr_event *e = ev_reserve(EV_MPROTECT_WX);
    if (!e) return 0;
    fill_meta(e);
    e->data.mprot.addr = (__u64)ctx->args[0];
    e->data.mprot.len  = (__u64)ctx->args[1];
    e->data.mprot.prot = prot;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kretprobe/__x64_sys_memfd_create")
int krp_memfd(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    if (ret < 0) return 0;
    burst_add(bw_memfd);
    struct edr_event *e = ev_reserve(EV_MEMFD_CREATE);
    if (!e) return 0;
    fill_meta(e);
    e->data.memfd.ret_fd = (__u32)ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/commit_creds")
int kp_commit_creds(struct pt_regs *ctx) {
    struct cred *newc = (struct cred *)PT_REGS_PARM1(ctx);
    if (!newc) return 0;
    __u32 nu = BPF_CORE_READ(newc, uid.val);
    __u32 cu = (__u32)bpf_get_current_uid_gid();
    if (nu != 0 || cu == 0) return 0;
    burst_add(bw_creds);
    struct edr_event *e = ev_reserve(EV_COMMIT_CREDS);
    if (!e) return 0;
    fill_meta(e);
    e->data.creds.old_uid = cu;
    e->data.creds.new_uid = nu;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/security_bpf")
int kp_sec_bpf(struct pt_regs *ctx) {
    __u32 cmd = (__u32)PT_REGS_PARM1(ctx);
    burst_add(bw_secbpf);
    struct edr_event *e = ev_reserve(EV_SEC_BPF);
    if (!e) return 0;
    fill_meta(e);
    e->data.unshare_ev.flags = cmd;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int kp_tcp_conn(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;
    __u16 fam = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (fam != AF_INET) return 0;
    burst_add(bw_connect);
    struct edr_event *e = ev_reserve(EV_TCP_CONNECT);
    if (!e) return 0;
    fill_meta(e);
    e->data.net.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->data.net.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u16 dp = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->data.net.dport = (dp << 8) | (dp >> 8);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int enforcement_live(void) {
    __u32 z = 0;
    __u32 *v = bpf_map_lookup_elem(&enforce_on, &z);
    return v && *v;
}

static __always_inline int is_blocked(void) {
    if (in_self_tree()) return 0;
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pt >> 32);
    if (bpf_map_lookup_elem(&exempt_tgids, &tgid)) return 0;
    if (bpf_map_lookup_elem(&blocked_tgids, &tgid)) return 1;
    if (!block_descendants) return 0;
    struct task_struct *t = bpf_get_current_task_btf();
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (!t) break;
        t = BPF_CORE_READ(t, real_parent);
        if (!t) break;
        __u32 ptg = BPF_CORE_READ(t, tgid);
        if (ptg == 0 || ptg == 1) break;
        if (bpf_map_lookup_elem(&exempt_tgids, &ptg)) return 0;
        if (bpf_map_lookup_elem(&blocked_tgids, &ptg)) return 1;
    }
    return 0;
}

static __always_inline void emit_deny(__u8 klass) {
    if (!emit_deny_events) return;
    struct edr_event *e = ev_reserve(EV_LSM_DENY);
    if (!e) return;
    fill_meta(e);
    e->data.deny.klass = klass;
    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm, struct linux_binprm *bprm, int ret) {
    if (ret != 0) return ret;
    if (!deny_exec || !enforcement_live()) return 0;
    if (!is_blocked()) return 0;
    emit_deny(DK_EXEC);
    return -EPERM;
}

SEC("lsm/file_mprotect")
int BPF_PROG(lsm_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret) {
    if (ret != 0) return ret;
    if (!deny_wx || !enforcement_live()) return 0;
    if (!((prot & 0x2) && (prot & 0x4))) return 0;
    if (!is_blocked()) return 0;
    emit_deny(DK_WX);
    return -EPERM;
}

SEC("lsm/mmap_file")
int BPF_PROG(lsm_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret) {
    if (ret != 0) return ret;
    if (!deny_wx || !enforcement_live()) return 0;
    if (!((prot & 0x2) && (prot & 0x4))) return 0;
    if (!is_blocked()) return 0;
    emit_deny(DK_WX);
    return -EPERM;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(lsm_setuid, struct cred *new, const struct cred *old,
             int flags, int ret) {
    if (ret != 0) return ret;
    if (!deny_setuid || !enforcement_live()) return 0;
    __u32 nu = BPF_CORE_READ(new, uid.val);
    __u32 ou = BPF_CORE_READ(old, uid.val);
    if (!(nu == 0 && ou != 0)) return 0;
    if (!is_blocked()) return 0;
    emit_deny(DK_SETUID);
    return -EPERM;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace, struct task_struct *child, unsigned int mode, int ret) {
    if (ret != 0) return ret;
    if (!deny_ptrace || !enforcement_live()) return 0;
    if (!is_blocked()) return 0;
    emit_deny(DK_PTRACE);
    return -EPERM;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_connect, struct socket *sock, struct sockaddr *address,
             int addrlen, int ret) {
    if (ret != 0) return ret;
    if (!deny_connect || !enforcement_live()) return 0;
    __u16 fam = BPF_CORE_READ(address, sa_family);
    if (fam != AF_INET && fam != AF_INET6) return 0;
    if (!is_blocked()) return 0;
    emit_deny(DK_CONNECT);
    return -EPERM;
}
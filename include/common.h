#ifndef EDR_COMMON_H
#define EDR_COMMON_H

#ifdef EDR_BPF_SIDE
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

#define MAX_ARG_LEN 256
#define MAX_PATH_LEN 256
#define MAX_COMM 16
#define MAX_NAME 64
#define BURST_FP_SCALE 65536

enum edr_ev_type {
    EV_FORK          = 1,
    EV_EXIT          = 2,
    EV_EXEC          = 3,
    EV_MPROTECT_WX   = 4,
    EV_MEMFD_CREATE  = 5,
    EV_PRCTL_RENAME  = 6,
    EV_PTRACE        = 7,
    EV_COMMIT_CREDS  = 8,
    EV_UNSHARE       = 9,
    EV_SEC_BPF       = 10,
    EV_TCP_CONNECT   = 11,
    EV_LSM_DENY      = 12,
    EV_BURST_TRIP    = 13
};

enum edr_deny_klass {
    DK_EXEC    = 1,
    DK_WX      = 2,
    DK_SETUID  = 3,
    DK_PTRACE  = 4,
    DK_CONNECT = 5
};

struct file_id {
    __u64 ino;
    __u64 size;
    __u64 mtime_ns;
    __u32 dev_major;
    __u32 dev_minor;
} __attribute__((aligned(8)));

struct exec_ctx {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    char  args[MAX_ARG_LEN];
} __attribute__((aligned(8)));

struct blk_val {
    __u64 armed_ns;
    __u8  mode;
    __u8  _pad[7];
} __attribute__((aligned(8)));

struct burst_val {
    __u64 sum_fp;
    __u32 epoch;
    __u32 _pad;
} __attribute__((aligned(8)));

struct edr_event {
    __u8  ev_type;
    __u8  _pad0[7];
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 pgid;
    __u32 uid;
    __u32 ns_inum;
    __u32 _pad1;
    char  comm[MAX_COMM];
    union {
        struct { char argbuf[MAX_ARG_LEN]; char filename[MAX_PATH_LEN]; struct file_id fid; } exec;
        struct { __u64 addr; __u64 len; __u32 prot; __u32 _p; } mprot;
        struct { __u32 ret_fd; __u32 _p; char name[MAX_NAME]; } memfd;
        struct { char new_name[MAX_COMM]; } rename;
        struct { __u32 tgt_pid; __u32 req; } ptrace_ev;
        struct { __u32 old_uid; __u32 new_uid; } creds;
        struct { __u32 flags; __u32 _p; } unshare_ev;
        struct { __u32 daddr; __u16 dport; __u16 _p; __u32 saddr; } net;
        struct { __u8 klass; __u8 _p[7]; } deny;
        struct { __u32 weight_fp; __u32 _p; } burst;
        __u8  _raw[MAX_ARG_LEN + MAX_PATH_LEN + 32];
    } data __attribute__((aligned(8)));
} __attribute__((aligned(8)));

#endif
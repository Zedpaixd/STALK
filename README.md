# EDR

eBPF endpoint detection and response framework: kernel sensors, a lineage-aware risk engine, in-kernel enforcement, a seccomp supervision harness, hash-keyed reputation, and an FTXUI terminal dashboard.

Target platform: WSL 2 (Kali / Ubuntu 22.04), kernel 6.18+. Runs on bare-metal Linux with the same requirements. See [Limitations](#limitations).

---

## Contents

- [Overview](#overview)
- [Kernel sensors](#kernel-sensors)
- [BPF maps](#bpf-maps)
- [Risk model](#risk-model)
- [Binary identity pipeline](#binary-identity-pipeline)
- [Response mechanisms](#response-mechanisms)
- [Self-exemption](#self-exemption)
- [Requirements](#requirements)
- [Build and run](#build-and-run)
- [Dashboard](#dashboard)
- [Supervised mode](#supervised-mode)
- [Reputation store](#reputation-store)
- [Configuration](#configuration)
- [Diagnostics](#diagnostics)
- [File layout](#file-layout)
- [Limitations](#limitations)
- [Roadmap](#roadmap)

---

## Overview

- Observes process lifecycle and security-relevant syscalls via eBPF.
- Models each process as a node in a lineage tree with a risk score in `[0, 1]`.
- Decays risk over time; backpropagates a fraction of each child's evidence to its ancestors.
- Identifies binaries by inode identity captured at exec, hashed asynchronously.
- Responds via scoring, interactive prompts, in-kernel burst blocking, BPF-LSM syscall denial, and process-group termination.
- Supervises operator-launched processes under seccomp user-notify, freezing each gated syscall for adjudication.

---

## Kernel sensors

| Hook | Type | Purpose |
|---|---|---|
| `sched_process_fork` | tracepoint | lineage node creation |
| `sched_process_exit` | tracepoint | mark node dead |
| `sys_enter_execve` | tracepoint | stash argv into `exec_state` |
| `sys_enter_execveat` | tracepoint | stash argv into `exec_state` |
| `sched_process_exec` | tracepoint | EXEC event, resolved filename, inode identity |
| `sys_enter_prctl` | tracepoint | `PR_SET_NAME` rename / masquerade |
| `sys_enter_ptrace` | tracepoint | debugger attach |
| `sys_enter_unshare` | tracepoint | namespace creation |
| `sys_enter_mprotect` | tracepoint | W^X transitions |
| `__x64_sys_memfd_create` | kretprobe | fileless execution |
| `commit_creds` | kprobe | privilege escalation to UID 0 |
| `security_bpf` | kprobe | eBPF program loading |
| `tcp_v4_connect` | kprobe | outbound connections |
| `bprm_check_security` | BPF-LSM | deny exec of blocked processes |
| `file_mprotect` | BPF-LSM | deny W^X |
| `mmap_file` | BPF-LSM | deny W^X |
| `task_fix_setuid` | BPF-LSM | deny setuid to root |
| `ptrace_access_check` | BPF-LSM | deny ptrace |
| `socket_connect` | BPF-LSM | deny connect |

Exec is emitted from `sched_process_exec`, not `sys_enter_execve`. The syscall entry hook fires before the binary is opened, so the path and inode are not yet resolvable, and it fires on failed execs.

## BPF maps

| Map | Type | Purpose |
|---|---|---|
| `rb` | ringbuf | kernel to userspace event channel |
| `exec_state` | LRU hash | per-task argv between execve entry and exec completion |
| `exec_stage` | percpu array | argv staging buffer (BPF stack is 512 bytes) |
| `blocked_tgids` | hash | enforcement targets |
| `exempt_tgids` | LRU hash | trusted processes |
| `enforce_on` | array | global enforcement switch |
| `burst_win` | LRU hash | per-process weighted syscall sum |
| `burst_epoch` | array | sliding window epoch, bumped from userspace |

---

## Risk model

Six category accumulators per node: Lifecycle, Execution, Memory, Privilege, Evasion, C2.

1. Decay accumulators by a per-category half-life.
2. Scale the event LLR by context multipliers (UID 0, cross-namespace, short-lived).
3. Squash each accumulator into a bounded contribution (`max_llr`, `scale`).
4. Add a corroboration bonus when two or more categories are active.
5. Map summed log-odds through a numerically stable sigmoid.

Backpropagation sends `backprop_factor` (default 0.25) of each node's evidence to its parent, recursively to `backprop_max_depth` (default 3), stopping at exempt nodes.

Audit-log stage string `st=XMPE` indicates active categories: **L**ifecycle, e**X**ecution, **M**emory, **P**rivilege, **E**vasion, **C**2.

---

## Binary identity pipeline

Reputation verdicts are keyed on SHA-256. A short-lived process is gone before its ring-buffer event is consumed, so identity capture cannot depend on the process being alive at decision time.

1. `sched_process_exec` reports `(dev_major, dev_minor, ino, size)` read from `mm->exe_file`, plus the kernel's resolved filename.
2. The ring-buffer callback immediately opens an fd, before any locking: `/proc/<pid>/exe` first, then the reported path. `fstat` must match the kernel-reported identity or the open is rejected.
3. The fd is handed to a worker thread pool. Hashing never runs on the consumer thread and never under the tracker lock.
4. Hashes are cached by inode key, not by pid. Repeat executions cost nothing.
5. On fork, the child inherits the parent's identity record; an exec replaces it.
6. Prompt construction walks the lineage as a backstop for a dropped fork event.
7. Decisions read the cached hash, or wait on the in-flight hash with a 3 s bound. No `/proc` access at keypress time.

Holding the fd removes the deadline entirely: the inode stays alive even if the file is unlinked. The `fstat` verification means a pid that no longer refers to the expected process is rejected rather than hashed.

---

## Response mechanisms

| Mechanism | Trigger | Effect |
|---|---|---|
| Passive scoring | always | no action |
| Auto-kill | risk >= `kill_threshold` for `dwell_sec` | `SIGKILL` to process group |
| Interactive prompt | risk >= `prompt_threshold` on a high-LLR event | `SIGSTOP`, modal decision |
| Burst auto-block | weighted syscall sum >= `burst_ceiling` in window | in-kernel block, then prompt |
| BPF-LSM denial | process in `blocked_tgids` | `-EPERM` on exec, W^X, setuid, ptrace, connect |
| Reputation | hash match on exec | silent block or silent exempt |
| Session allow | operator presses `w` | in-memory trust by inode, until restart |

Prompt actions: `y` allow, `n` deny, `b` block-and-resume, `k` kill, `d` blacklist, `l` whitelist, `w` session-allow, `Esc` dismiss.

---

## Requirements

- Root inside the environment.
- BTF: `/sys/kernel/btf/vmlinux` present.
- BPF-LSM active: `bpf` in `/sys/kernel/security/lsm`. Without it, scoring and prompts work; LSM denial and burst blocking are inert.
- tracefs mounted: `sudo mount -t tracefs nodev /sys/kernel/tracing`
- Toolchain: `clang`, `bpftool`, `cmake`, `gcc`, `g++`.

Run `./run_me.sh --check-env` for a read-only report.

---

## Build and run

```sh
./run_me.sh --setup          # first-time: toolchain, BTF, vmlinux.h, FTXUI, json.hpp
./run_me.sh --edr            # build if needed, launch
./run_me.sh --recompile      # fast rebuild
./run_me.sh --clean-build    # wipe build/ and bin/, rebuild
./run_me.sh --supervise      # guided supervised flood demo
./run_me.sh --clean          # remove build/ and bin/
```

Direct launch, bypassing the driver:

```sh
sudo ./build/edr rules.json
```

### Rebuilding after BPF changes

The skeleton is generated to `include/edr.skel.h`, not into `build/`. CMake does not track `common.h` as a dependency of the skeleton target, so a stale skeleton survives a normal rebuild and the kernel and userspace disagree on the event struct layout.

```sh
rm -f include/edr.skel.h && sudo make
```

Symptom of a stale skeleton: every process reads `0.0%`, or BPF changes have no observable effect.

---

## Dashboard

Left pane is the lineage tree; right column holds threat gauges, the watchlist, the masquerade log, and the audit log.

| Key | Action |
|---|---|
| `j` / `k`, arrows | move selection |
| `g` / `G` | top / bottom |
| `n` / `a` | new-only / all |
| `PgUp` / `PgDn`, `Home` / `End` | scroll audit log, `End` follows live |
| `Space` | pause / resume view |
| `e` | toggle kernel enforcement |
| `X` | clear active blocks |
| `D` | purge dead nodes |
| `S` | launch supervised process |
| `o` | supervised output view |
| `R` | reputation manager |
| `?` | full keybind list |
| `q` | quit |

Tree tags: `(WATCHED)` supervised, `(BLOCKED)` LSM-blocked, `(FROZEN)` awaiting decision, `(dead)` exited. `*` marks a new process. A `sub NN%` chip on a launcher shows its riskiest descendant.

Keybindings are loaded from `binds.json` and validated at startup; conflicts prompt to fall back to defaults.

---

## Supervised mode

Press `S` and enter a command. The target runs on a PTY under a seccomp user-notify filter. Each gated syscall is held in-kernel and raises a modal showing the syscall, its arguments, the resolved path, the process's current eBPF risk, and the risk that allowing it would produce.

In the output view (`o`): `i` writes to stdin, `u` toggles auto-allow for syscalls the model does not score, `Esc` closes.

Gated syscalls: `memfd_create`, `mprotect`, `ptrace`, `unshare`, `connect`, `execveat`, `prctl`.

A standalone harness is also available:

```sh
sudo ./bin/edr_run -- ./bin/flood_trigger /tmp/x.txt 1
```

---

## Reputation store

Persisted at `/etc/edr/reputation.json`, keyed on SHA-256.

- `kind: 0` blacklist, `kind: 1` whitelist, plus `paused`.
- Checksum verified on load; mismatch raises a tamper flag.
- Made immutable (`chattr +i`) between writes where supported.
- Whitelist is checked before blacklist.

Manage with `R`: `p` pauses or resumes a rule, `x` removes it. The manager lists persisted entries first, then session-allow entries below a separator. Session entries are in-memory only and are never written to disk.

If writes wedge:

```sh
sudo chattr -i /etc/edr/reputation.json
```

---

## Configuration

`rules.json`, loaded at startup only.

| Group | Keys |
|---|---|
| `engine_config` | `prior_logodds`, `corrob_coeff`, `active_floor`, `backprop_factor`, `backprop_max_depth`, `warmup_sec`, `dwell_sec`, `tick_ms` |
| `categories` | per-category `max_llr`, `scale`, `half_life_sec` |
| `event_llr` | per-event LLR contribution; `0` makes an event unmonitored |
| `context_multipliers` | `uid_0`, `cross_ns`, `short_lived` |
| `prompt_config` | `enabled`, `prompt_threshold`, `prompt_event_floor`, `auto_kill_enabled`, per-decision actions |
| `enforcement` | `enabled`, per-class deny flags, `block_descendants`, `burst` |
| `enforcement.burst` | `ceiling`, `window_ms`, per-event `weights` |
| GC | `gc_base_ttl_sec`, `gc_peak_ttl_coeff`, `gc_forensic_keep`, `gc_tomb_risk_floor` |
| `exempt_comms` | process names always trusted |
| `reputation` | `store_path` |

To reduce prompt noise, raise `prompt_event_floor` so only high-LLR events can trigger a freeze, or raise `prompt_threshold`.

---

## Diagnostics

Userspace instrumentation goes to stderr. libbpf CO-RE output shares the stream.

```sh
sudo ./build/edr rules.json 2>/tmp/edr.log
grep -E 'PRIME|EXEC-CAPTURE|INHERIT|ENQUEUE-PROMPT|RESOLVE-REP' /tmp/edr.log
```

| Tag | Meaning |
|---|---|
| `PRIME` | identity captured at exec; `fd` >= 0 means the open succeeded, `via` names the route |
| `EXEC-CAPTURE` | identity attached to the node |
| `INHERIT` | forked child inherited the parent's identity |
| `PROMPT-INHERIT` | identity recovered by lineage walk at prompt time |
| `ENQUEUE-PROMPT` | `fid_valid` and `hash` show whether the decision can persist |
| `RESOLVE-REP` | final outcome of a blacklist or whitelist keypress |

Kernel-side `bpf_printk` output:

```sh
sudo cat /sys/kernel/tracing/trace_pipe
```

---

## File layout

```
run_me.sh                 build/check/run driver [you mainly interact with this]
setup.sh                  toolchain, BTF, FTXUI, json.hpp
Makefile / CMakeLists.txt BPF compile, skeleton gen, C++17 target
rules.json                engine config, weights, thresholds, burst, GC
binds.json                keybindings
include/common.h          shared event schema, aligned(8)
bpf/edr.bpf.c             sensors, LSM enforcement, burst blocker
src/main.cpp              skeleton lifecycle, threads, signals
src/tracker.{h,cpp}       lineage, scoring, backprop, prompts, identity records
src/math_engine.{h,cpp}   sigmoid, decay, category contribution, config loader
src/hasher.{h,cpp}        verified fd open, worker pool, inode-keyed hash cache
src/reputation.{h,cpp}    hash-keyed store, checksum, immutability
src/seccomp_supervisor.{h,cpp}  seccomp user-notify harness
src/seccomp_filter.cpp    filter construction, fd passing
src/seccomp_harness.cpp   standalone CLI harness
src/keymap.{h,cpp}        keybind table, binds.json loader
src/ui.{h,cpp}            dashboard and modals
src/ui_repman.cpp         reputation manager, keybind help
src/sha256.{h,cpp}        SHA-256
test/                     benign syscall-flood triggers and runners
```

---

## Limitations

- **Fail-open verdict window.** Reputation lookup does not block on hashing, so   a blacklisted binary may execute for the few milliseconds before its hash resolves; it is then blocked retroactively. Blocking exec until the verdict is known would require a sleepable LSM program and risks stalling exec system-wide.
- **Identity is `dev + ino + size`.** `inode.i_mtime` was renamed in kernel 6.6 and split in 6.11, so mtime is not read. A same-size, same-inode modification between exec and hash is not detected.
- **Namespaced pids are partial.** Only `in_self_tree` translates to the agent's pid namespace. Event `pid`, `tgid`, `ppid`, and `pgid` are still reported in the initial namespace, so tasks outside the agent's namespace cannot be correlated with `/proc`.
- **One supervised process at a time.** Launching a second while one is active is rejected.
- **Display lag on death.** The tree can briefly show an exited process until `sched_process_exit` is ingested. `D` purges on demand.
- **Thread nodes.** `sched_process_fork` fires for thread creation, so threads appear as child nodes of their process.
- **BPF-LSM dependency.** Without `bpf` in the active LSM set, denial and burst blocking are inert.
- **kprobe availability.** Missing symbols on custom kernels log `[hook] FAIL` and the tool continues with the hooks that attached. Only ring-buffer creation failure is fatal.
- **Not validated on bare metal.** All behaviour above is observed under WSL 2.

---

## Roadmap

Detection:

- Un-exempt `python`, `perl`, `node`
- Backpropagate through exempt ancestors
- `tcp_v6_connect` sensor
- `mmap` W^X as a scoring sensor, not only an enforcement hook
- Gate `execve` in the seccomp filter, not only `execveat`

Hardening:

- Pin BPF links to bpffs
- Persist the audit log to disk
- Kernel-side `SIGKILL` via `bpf_send_signal`
- Track `common.h` as a skeleton dependency in CMake

Features:

- Kill, whitelist, and blacklist directly from the lineage tree
- Allow concurrent supervised processes
- Distinguish "allow this syscall" from "allow this process" in the eBPF modal
- In-kernel content hashing to remove the userspace identity race entirely
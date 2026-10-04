# Phantom

## Overview

**Phantom** is a Linux memory-forensics Sherlock focused on a compromised Ubuntu server exhibiting suspicious outbound connections and incomplete output from standard diagnostic commands.

Analysis of the supplied memory image identified a hidden, unsigned kernel module named **`singularity`**. The module uses **ftrace-based hooks** rather than replacing entries in the syscall table, allowing it to interfere with process, filesystem, and network visibility while keeping the syscall table itself apparently intact.

The investigation also recovered three compromised `bash` processes connected to a C2 endpoint, evidence of a privilege-escalation backdoor, a hooked process-fork tracepoint, and enough of the hidden module's memory to perform a limited Ghidra review.

---

## Evidence set

| Artifact | Description |
|---|---|
| `dump_srv.mem` | Linux physical memory image |
| `Ubuntu_6.8.0-87-generic.json` | Volatility 3 Linux symbols |
| Volatility | 3 Framework 2.27.0 |
| Kernel | Ubuntu `6.8.0-87-generic` |
| Architecture | x86-64 |

The supplied symbol file matched the kernel banner recovered from memory.

---

## High-level findings

### Hidden kernel module

Volatility's hidden-module scan recovered:

| Field | Value |
|---|---|
| Module | `singularity` |
| Module structure | `0xffffc0b42640` |
| Code base | `0xffffc0b35000` |
| Size | `0x19000` |
| Taints | `OOT_MODULE,UNSIGNED_MODULE` |
| Load time | `2490.473832` seconds since boot |
| Loading PID | `2669` |

Kernel messages showed the module being loaded out of tree and failing signature verification.

### Hooking architecture

The normal syscall table did not show direct replacement of key entries such as `connect`, `getdents`, or `getdents64`.

Instead, `linux.tracing.ftrace.CheckFtrace` identified **82 ftrace hooks** associated with `singularity`, all using the same centralized callback:

`0xffffc0b3aac0`

Important hooked functions included:

- `tcp4_seq_show` — IPv4 connection visibility.
- `tcp6_seq_show` — IPv6 connection visibility.
- `icmp_rcv` — ICMP receive path and covert-channel capability.
- Five `getdents`-family syscall variants — directory and `/proc` filtering.
- `__x64_sys_kill` — process-control/backdoor behavior.
- BPF-related syscalls.
- Module-loading syscalls.
- File open/stat/read/write paths.
- `io_uring_enter` and several data-movement functions.

A separate tracepoint check showed that `singularity` also hooked:

`sched_process_fork`

This combination explains why standard diagnostic tools could return incomplete information without an obviously modified syscall table.

---

## C2 and compromised shells

Socket reconstruction identified three `bash` processes whose standard file descriptors were attached directly to the same established TCP connection destination:

| PID | Connection |
|---|---|
| `2693` | `192.168.200.177:48440 -> 192.168.200.164:8081` |
| `2695` | `192.168.200.177:48444 -> 192.168.200.164:8081` |
| `2698` | `192.168.200.177:48454 -> 192.168.200.164:8081` |

The C2 endpoint was therefore:

`192.168.200.164:8081/TCP`

`PsAux` also associated these shells with the argument `singularity`, strengthening the link between the module and the remote shell activity.

---

## Privilege escalation evidence

Bash history recovered the following sequence:

```text
OPERATOR=access bash
kill -59 $$
internal_fifos
ps aufwx
```

The child shell (PID `2792`) had root credentials in the process list, while its environment still contained:

```text
USER=workstation
LOGNAME=workstation
HOME=/home/workstation
OPERATOR=access
```

Targeted strings from the rootkit memory also exposed artifacts such as:

- `/root/Singularity/modules/become_root.c`
- `hook_kill`
- `become_root_init`
- `become_root_exit`
- `hidden_pids.c`
- `add_hidden_pid`

Taken together, the evidence strongly supports a privilege-escalation backdoor involving the environment value **`access`** and the hooked `kill` path. The exact internal implementation was not fully reconstructed from the incomplete raw module image.

---

## Optional reversing

Volatility could identify the hidden module but could not reconstruct a valid ELF with `Hidden_modules --dump` or `ModuleExtract`.

The module's mapped region was therefore carved manually from the kernel virtual layer. Missing pages were padded with zeroes, producing a **102,400-byte** raw image.

The raw image contained strings and function-name artifacts including:

```text
singularity_exit
hook_kill
hook_icmp_rcv
orig_icmp_rcv
become_root_init
become_root_exit
is_hidden_pid
add_hidden_pid
hidden_pids
```

It was imported into Ghidra as x86-64 little-endian raw binary with the canonical image base:

`0xffffffffc0b35000`

Ghidra recovered 74 candidate functions. Review of the callback at canonical address `0xffffffffc0b3aac0` showed behavior consistent with a shared ftrace thunk that checks whether a caller belongs to the module's own address ranges before redirecting execution.

Because the carve contains padded missing pages and lacks the original ELF metadata, this reversing result is treated as supporting evidence rather than a complete reconstruction.

---

## Repository contents

- [Memory analysis](./memory-analysis.md)
- [Findings and challenge answers](./findings.md)
- [Optional reversing notes](./reversing-notes.md)

---

## Scope note

This write-up distinguishes direct evidence from inference. Conclusions are limited to artifacts recoverable from the provided memory image and the manually carved module region.

# PhantomRing

## Overview

**PhantomRing** is a Linux malware-analysis Sherlock focused on a custom ELF agent that communicates with a hard-coded command-and-control server and uses **io_uring** extensively for file, socket, and process-related operations.

The sample implements a compact C2 command set for host reconnaissance, file transfer, session manipulation, privilege-escalation reconnaissance, defense evasion, and self-deletion.

This write-up documents both the **static analysis** and the **dynamic validation** performed in an isolated REMnux lab.

---

## Sample information

| Field | Value |
|---|---|
| Filename | `agent` |
| Type | ELF 64-bit LSB PIE executable |
| Architecture | x86-64 |
| Linking | Dynamically linked |
| Symbols | Not stripped |
| Interpreter | `/lib64/ld-linux-x86-64.so.2` |
| SHA-256 | `2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5` |
| Build ID | `1f617f2ea259a7ec724d7bbc01627982dc2f0495` |
| C2 | `192.168.56.1:4445/TCP` |
| Reconnect delay | 120 seconds |
| Key dependency | `liburing.so.2` |

---

## High-level behavior

The agent:

- Connects to a hard-coded C2 over TCP.
- Uses **io_uring** for many socket and file operations.
- Accepts 11 logical commands.
- Enumerates users, processes, TCP connections, and SUID binaries.
- Supports bidirectional file transfer.
- Can terminate a selected PTS session.
- Contains functionality intended to interfere with tracing/eBPF-based monitoring.
- Can terminate cleanly or delete its own executable and exit.

---

## Supported C2 commands

| Command | Purpose |
|---|---|
| `get` | Read a local file and send it to the C2 |
| `recv` | Receive bytes from the C2 and write them to a local file |
| `users` | Enumerate logged-in users from `/var/run/utmp` |
| `ss` | Enumerate TCP connections from `/proc/net/tcp` |
| `netstat` | Alias of `ss` |
| `ps` | Enumerate processes using `/proc/<pid>/comm` |
| `me` | Return the agent PID and associated TTY |
| `kick` | List PTS sessions or kill the process associated with a selected PTS |
| `privesc` | Enumerate SUID binaries under `/usr/bin` |
| `sdestruct` | Delete the running executable and terminate |
| `killbpf` | Attempt to impair tracing/eBPF monitoring |
| `exit` | Disconnect and terminate without deleting the binary |

`ss` and `netstat` use the same handler, so they count as a single logical capability.

---

## Key findings

### io_uring usage

The malware relies heavily on `io_uring` rather than conventional blocking I/O wrappers for several operations. During static analysis this was visible through calls such as:

- `io_uring_prep_connect`
- `io_uring_prep_recv`
- `io_uring_prep_send`
- `io_uring_prep_read`
- `io_uring_prep_write`
- `io_uring_prep_openat`
- `io_uring_prep_unlinkat`

This is relevant because the sample is explicitly designed around a Linux kernel I/O interface that can reduce visibility for monitoring approaches focused narrowly on traditional syscall interception.

### Defense evasion

The `killbpf` handler was not executed dynamically because it can alter the analysis environment. Static reversing showed attempts to:

- Write to `/sys/kernel/debug/tracing/tracing_on`
- Write to `/sys/kernel/debug/tracing/set_event`
- Write to `/sys/kernel/debug/tracing/current_tracer`
- Enumerate and unlink objects under `/sys/fs/bpf`
- Search `/proc/<pid>/maps` for `anon_inode:bpf-map`
- Kill matching processes with `SIGKILL`

---

## Dynamic validation

The sample was executed inside an isolated REMnux VM. A local loopback address was used to emulate the hard-coded C2:

```text
192.168.56.1:4445
```

The following behaviors were validated successfully:

- C2 connection established.
- `me` returned the malware PID and TTY.
- `users` enumerated active sessions.
- `ps` enumerated processes.
- `ss` and `netstat` returned TCP connection information.
- `get /etc/hostname` returned the file contents.
- `privesc` returned SUID binaries.
- `kick` listed active PTS sessions.
- `recv` successfully wrote a 6-byte test file.
- `exit` terminated the agent without deleting it.
- `sdestruct` deleted a copied sample from disk and terminated.

The `killbpf` capability was intentionally **not executed**.

---

## Repository contents

- [Static analysis](./static-analysis.md)
- [Dynamic analysis](./dynamic-analysis.md)
- [Indicators and artifacts](./iocs.md)

---

## Lab safety

The sample was executed only in an isolated malware-analysis VM with no default route to the Internet. The C2 IP was bound locally to loopback so the malware could be interacted with without exposing the sample to an external network.

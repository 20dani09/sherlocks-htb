# PhantomRing — Static Analysis

## Initial triage

```bash
file agent
```

Result:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, GNU/Linux 3.2.0, not stripped
```

The binary is not stripped, which made function-level reversing significantly easier.

---

## Interesting strings

Static strings revealed several important paths and command names:

```text
/var/run/utmp
/proc/net/tcp
/proc/%ld/comm
/proc/%ld/fd
/usr/bin
/proc/self/exe
/sys/kernel/debug/tracing/tracing_on
/sys/kernel/debug/tracing/set_event
/sys/kernel/debug/tracing/current_tracer
/sys/fs/bpf
/proc/%s/maps
anon_inode:bpf-map
192.168.56.1
```

Command strings:

```text
get
recv
users
ss
netstat
ps
me
kick
privesc
sdestruct
killbpf
exit
```

---

## C2 configuration

Reversing `main` showed:

- Hard-coded IP: `192.168.56.1`
- Port: `0x115d` → decimal `4445`
- Transport: TCP
- Reconnect delay after failure: `0x78` → 120 seconds

---

## Command dispatcher

`process_cmd` sanitizes the incoming command and dispatches it to dedicated handlers.

The malware supports **11 logical capabilities**. `ss` and `netstat` are aliases and call the same handler.

Invalid input results in:

```text
[*] 404 Command not found [*]
```

---

## Function analysis

### sanitize_cmd

Removes trailing:

- newline `0x0A`
- carriage return `0x0D`
- space `0x20`

### trim_leading

Advances a supplied string pointer past leading whitespace using the libc character classification table.

### read_file_uring

Generic file-reading helper:

1. Opens a path with `io_uring_prep_openat`.
2. Reads data with `io_uring_prep_read`.
3. Repeats until EOF or the maximum buffer size.
4. Null-terminates the output.
5. Closes the descriptor.

Used for several pseudo-files under `/proc` and for `/var/run/utmp`.

### send_all

Reliable send loop implemented with `io_uring_prep_send`. It continues until the requested number of bytes has been transmitted or an error occurs.

### recv_all

Despite the name, this helper performs a single receive operation using `io_uring_prep_recv` and returns the completion result.

---

## Command handlers

### get

Reads a requested local file in chunks up to 64 KiB and sends the content to the C2.

Direction:

```text
victim → C2
```

### recv

Receives an operator-supplied path and size, opens the destination with:

```text
O_WRONLY | O_CREAT | O_TRUNC
```

using mode `0644`, then receives data in chunks up to 64 KiB and writes it to disk.

Direction:

```text
C2 → victim
```

### users

Reads `/var/run/utmp`, filters entries where `ut_type == USER_PROCESS`, and returns username and terminal information.

### ss / netstat

Reads `/proc/net/tcp` directly and parses:

- local IPv4 address and port
- remote IPv4 address and port
- TCP state
- UID

It does not execute the system `ss` or `netstat` utilities.

### ps

Enumerates numeric directories under `/proc` and reads:

```text
/proc/<pid>/comm
```

to build a process list.

It does not execute `ps`.

### me

Returns:

- the current process ID via `getpid()`
- the TTY attached to stdin via `ttyname(0)`

### kick

Without an argument, lists entries under `/dev/pts`.

With a target PTS, it enumerates `/proc/<pid>/fd`, resolves descriptor symlinks, finds a process associated with the selected terminal, and sends `SIGKILL`.

### privesc

Enumerates `/usr/bin` and checks file mode bits for the SUID flag.

It does **not** directly exploit a privilege-escalation vulnerability; it performs reconnaissance for possible escalation paths.

### sdestruct

1. Sends a self-destruct message to the C2.
2. Resolves its own path using `/proc/self/exe`.
3. Deletes the executable with `io_uring_prep_unlinkat`.
4. Exits.

### exit

Sends a disconnect message, closes the C2 socket, tears down the io_uring queue, and exits without deleting the executable.

### killbpf

Static analysis showed functionality intended to impair Linux tracing/eBPF visibility:

- attempts to modify tracing controls
- enumerates pinned BPF objects
- unlinks entries under `/sys/fs/bpf`
- scans process maps for `anon_inode:bpf-map`
- sends `SIGKILL` to matching processes

This handler was intentionally not executed during dynamic analysis.

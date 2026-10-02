# PhantomRing — Indicators and Artifacts

## Sample

| Type | Value |
|---|---|
| Filename | `agent` |
| SHA-256 | `2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5` |
| Build ID | `1f617f2ea259a7ec724d7bbc01627982dc2f0495` |
| Format | ELF 64-bit x86-64 PIE |
| Dependency | `liburing.so.2` |

## Network

| Type | Value |
|---|---|
| C2 IP | `192.168.56.1` |
| C2 port | `4445/TCP` |
| Reconnect delay | 120 seconds |

## Filesystem and procfs artifacts

```text
/var/run/utmp
/proc/net/tcp
/proc/<pid>/comm
/proc/<pid>/fd
/proc/<pid>/maps
/proc/self/exe
/usr/bin
/dev/pts
/sys/kernel/debug/tracing/tracing_on
/sys/kernel/debug/tracing/set_event
/sys/kernel/debug/tracing/current_tracer
/sys/fs/bpf
```

## Interesting string

```text
anon_inode:bpf-map
```

## C2 command vocabulary

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

## Behavioral detection ideas

Useful defensive pivots include:

- unexpected processes communicating with `192.168.56.1:4445`
- non-standard applications linking against `liburing.so.2`
- direct reads of `/proc/net/tcp`, `/var/run/utmp`, or large numbers of `/proc/<pid>/comm` files
- enumeration of `/usr/bin` followed by SUID checks
- access to `/sys/kernel/debug/tracing/*`
- unlink activity under `/sys/fs/bpf`
- process scans for `anon_inode:bpf-map`
- self-resolution via `/proc/self/exe` immediately followed by unlink/delete activity

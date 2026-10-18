# ShadowMonarch

**Hack The Box Sherlock · Linux malware reverse engineering · Passive backdoor · Classic BPF · RC4**

> **Key finding:** The sample installs a **30-instruction classic Berkeley Packet Filter** on a raw packet socket, allowing it to wait for a specially crafted activation packet without opening a conventional TCP listening port. In our isolated REMnux run, the filter was successfully attached and the malware reached `recvfrom()`. The reverse-shell, bind-shell and RC4 paths were recovered through static analysis, **not observed as live C2 sessions**.

## Overview

**ShadowMonarch** examines a 64-bit Linux ELF backdoor recovered from a memory-backed directory in a fictional telecommunications incident. The scenario describes unusual connections apparently associated with legitimate system processes, despite no corresponding EDR alert.

Our investigation combines **ELF inspection, disassembly, filter reconstruction and controlled syscall tracing**. It establishes how the implant stages itself under a system-like filename, hides its execution context, screens inbound traffic with BPF, and interprets activation messages to select remote-access functions.

Its architecture is consistent with the **BPFDoor-style passive backdoor technique**. That is a behavioral comparison, **not proof that this sample belongs to a particular publicly documented BPFDoor variant, campaign or threat actor**.

This write-up deliberately distinguishes **observed behavior**, **code-derived behavior**, and **unverified scenario details**.

---

## Why passive backdoors are different

Many remote-access implants maintain periodic connections to a command-and-control (C2) server or expose a service on a listening port. Those designs can produce useful detection signals: outbound beacons, repeated DNS lookups, an open socket in the `LISTEN` state, or a stable destination.

A **passive backdoor** reverses the relationship. It waits for a very specific inbound signal — frequently called a *magic packet* — before beginning an interactive session. During this dormant phase, there may be **no outbound beacon and no conventional TCP listener** to discover by port scanning.

| Conventional C2 pattern | Passive BPF-triggered pattern |
|---|---|
| Regular outbound communication may be visible | Implant can remain silent until triggered |
| An exposed service may appear in socket listings | Initial signaling uses a packet-capture socket |
| A fixed C2 endpoint may be embedded in the binary | The activation packet can supply an IP and port |
| Network indicators can be periodic | The important event may be a single unusual packet |

This does **not** make the implant invisible. Packet sockets, process ancestry, abnormal filesystem activity, BPF attachment and subsequent shell or firewall activity remain viable sources of evidence.

### What BPF does — and does not do

**Berkeley Packet Filter (BPF)** is a mechanism for deciding which packets a socket receives. This sample uses **classic BPF (cBPF)** through `SO_ATTACH_FILTER`. It is **not an eBPF rootkit** and our investigation found no basis to claim that it loads a malicious kernel module.

The kernel runs the socket filter against incoming packets. Only packets satisfying the filter are forwarded to the process, where **user-space code** parses the activation message and selects a behavior. The BPF program itself does not execute a shell.

~~~mermaid
flowchart TD
    A[Incoming IPv4 packet] --> B[AF_PACKET raw socket]
    B --> C{30-instruction classic BPF filter}
    C -->|No match| D[Discard for this socket]
    C -->|Match| E[recvfrom in user space]
    E --> F[Parse IP, port and control token]
    F -->|ph4nt0m_g4t3| G[Reverse TCP shell path]
    F -->|r3d_m3nsh3n| H[Bind shell / iptables path]
    F -->|Other token| I[One-byte UDP response]
~~~

The essential distinction is **packet selection versus protocol validation**: passing the BPF check is only the first gate.

---

## Evidence set and sample identity

| Item | Description |
|---|---|
| Sample filename | `shadow_monarch` |
| SHA-256 | `41de260cb5518df31ad437f4c0bf0fb2fea848e7648b1911658275da00f2fd16` |
| Size | 30,856 bytes |
| Format | ELF 64-bit LSB, x86-64, PIE, dynamically linked, stripped |
| ELF interpreter | `/lib64/ld-linux-x86-64.so.2` |
| Build ID (SHA-1) | `3b673cff1ac51d4714d7119d43e5cf9ba062aee7` |
| Lab environment | Isolated REMnux virtual machine |
| Dynamic evidence | Multi-process `strace -ff` output, `ss` and a small `tcpdump` PCAP |
| PCAP result | 116 bytes; one unrelated ICMPv6 Router Solicitation |
| Malware sample in repo | **Not included** |

**Evidence provenance:** The binary was examined statically; the execution traces and packet-capture observations came from the isolated REMnux run. No successful activation packet, interactive shell session or attacker-controlled IP address was present in the supplied traffic.

### Evidence-confidence guide

| Finding | Evidence | Assessment |
|---|---|---|
| Requires root for the main execution path | `getuid()` branch + non-root trace | **Static and dynamic** |
| Stages a copy under `/dev/shm` | `execve()` / `cp` / `rm` trace | **Observed** |
| Attaches a 30-instruction cBPF program | `setsockopt(SO_ATTACH_FILTER) = 0` | **Observed** |
| Magic values and packet fields | Filter instructions and payload parser | **Static reconstruction** |
| Two remote-shell modes and RC4 | Control-flow and crypto routines | **Static reconstruction** |
| Live C2 session or attacker infrastructure | No matching packets in lab capture | **Not observed** |

---

## Execution chain

The recovered startup sequence resembles a short-lived installer feeding a resident passive listener:

~~~text
shadow_monarch  [initial execution, UID 0]
    |
    +--> checks /var/run/systemd-private.pid
    |
    +--> /bin/sh -c ...
            |
            +--> remove previous /dev/shm/.systemd-runtime
            +--> copy ./shadow_monarch to /dev/shm/.systemd-runtime
            +--> chmod 755 on the copied ELF
            +--> execute /dev/shm/.systemd-runtime --init
            |       |
            |       +--> backdate file timestamps
            |       +--> fork / daemon-like behavior
            |       +--> create /var/run/systemd-private.pid
            |       +--> socket(AF_PACKET, SOCK_RAW, ETH_P_IP)
            |       +--> setsockopt(... SO_ATTACH_FILTER, len=30) = 0
            |       +--> recvfrom(...) [wait for matching traffic]
            |
            +--> unlink /dev/shm/.systemd-runtime
~~~

The deletion of the on-disk name is not equivalent to termination of the already-executing process. A Linux process can continue to run after its executable has been unlinked.

## Static reverse engineering

### ELF metadata and imported functions

The initial triage used ordinary read-only Linux utilities:

~~~bash
file shadow_monarch
sha256sum shadow_monarch
readelf -h shadow_monarch
readelf -Ws shadow_monarch
strings -a shadow_monarch
objdump -d -M intel shadow_monarch > shadow_monarch.asm
~~~

Because the ELF is **stripped**, descriptive symbols for its internal routines are absent. The dynamic import table nevertheless exposes useful behavioral leads:

| Imported APIs | Why they matter |
|---|---|
| `socket`, `setsockopt`, `recvfrom` | Raw traffic reception and socket filtering |
| `connect`, `bind`, `listen`, `accept` | Outbound and inbound session capabilities |
| `fork`, `execve`, `system` | Process creation and command execution |
| `getuid` | Privilege-dependent execution path |
| `prctl` | Process identity manipulation |
| `memcmp` | Validation of activation tokens |
| `utimes` | Timestamp manipulation |

Imports alone do not prove maliciousness. The useful evidence comes from **how these functions are combined and reached**.

### Root-only execution branch

Disassembly near `0x4edf` shows a call to `getuid()`, followed by a test against zero. The non-root path exits without reaching the network-listener functionality.

The first dynamic run corroborated this:

~~~text
getuid() = 1000
+++ exited with 0 +++
~~~

This is why launching the sample as the ordinary `remnux` user appeared to do nothing. A separate, controlled root execution was needed to observe its startup behavior.

### Strings assembled at runtime

The two activation tokens are **not simply stored as complete printable strings**. Immediate values in the executable build them in memory before comparison. This limits the usefulness of `strings` alone, but the assembled values can be recovered by following the disassembly around `0x4d56–0x4d7d`.

Recovered tokens:

- `ph4nt0m_g4t3` — reverse-shell branch
- `r3d_m3nsh3n` — bind-shell branch

The relevant user-space selection routine (approximately `0x352c`) uses `memcmp()` for the known token lengths. The inspected logic behaves like a **prefix check**, rather than a strict full-string equality check.

---

## The 30-instruction classic BPF filter

The filter is constructed in the binary around `0x35ba–0x39be` and attached through `setsockopt()` near `0x3a2b`. Its purpose is to accept particular **IPv4 TCP, UDP and ICMP** packets while dropping irrelevant traffic from the malware's socket.

| Filter step | Reconstructed behavior |
|---|---|
| Ethernet type | Check `0x0800` (IPv4) |
| IP protocol | Branch on TCP (6), UDP (17), or ICMP (1) |
| IPv4 fragmentation | Reject packets with a non-zero fragment offset (`0x1fff` mask); this is **not** a complete MF-flag check |
| UDP | Inspect the beginning of the UDP payload for `0x8337` |
| ICMP | Require Echo Request (type 8) and inspect its data for `0x8337` |
| TCP | Calculate TCP header length and inspect the beginning of TCP payload for `0x4141` |
| Accept | Return `0xffff` |
| Reject | Return `0` |

**Sample-specific activation signatures:**

| Protocol | Magic value | Bytes |
|---|---|---|
| TCP | `0x4141` | `41 41` |
| UDP | `0x8337` | `83 37` |
| ICMP | `0x8337` | `83 37` |

These are **this sample's values** and should not be mixed with signatures reported for other BPFDoor builds.

### What the filter reads

The following condensed sketch expresses the main decisions rather than reproducing every machine instruction:

~~~text
if EtherType != IPv4: reject
if IPv4 fragment offset != 0: reject

if UDP:
    require payload marker 0x8337
else if ICMP:
    require Echo Request and data marker 0x8337
else if TCP:
    compute actual TCP header length
    require payload marker 0x4141
else:
    reject

accept packet for user-space parsing
~~~

One implementation detail matters for reversing: cBPF uses packet offsets and header-length calculations. The filter accounts for the IPv4 header length, while parts of the **subsequent user-space parser** appear to assume a fixed 20-byte IPv4 header. Packets with IPv4 options could therefore be interpreted inconsistently.

A network scan that only checks for TCP listening ports would miss this initial trigger path. A defender should instead look for the **unexpected raw packet socket plus a selective BPF filter**.

---

## Activation packet format

After the filter accepts a packet, the user-space parser reads a compact control structure at the beginning of the transport payload.

| Offset | Size | Interpretation |
|---:|---:|---|
| `+0` | 2 bytes | Magic value for the relevant transport |
| `+2` | 2 bytes | Field observed in the structure; purpose not established |
| `+4` | 4 bytes | IPv4 address used for control/connection |
| `+8` | 2 bytes | Port, stored in network byte order |
| `+10` | Variable | NUL-terminated control token |

The IPv4 field supports a special value, `0xffffffff`, that causes the code to use the **source address of the incoming packet**. This helps explain why no fixed attacker IP was recovered from this ELF.

**Important distinction:** This structure is **inferred from code**, not decoded from a captured activation packet. The laboratory PCAP did not contain one. The parser also appears to perform limited length validation before consulting some fields; malformed inputs should not be assumed to work reliably.

### Control-flow branches

| Control token | Reconstructed behavior | Observed during lab run? |
|---|---|---|
| `ph4nt0m_g4t3` | Establish a reverse TCP session toward the address/port carried by the message, then enter the shell communication routine | No — static |
| `r3d_m3nsh3n` | Open a local bind-shell listener and temporarily redirect incoming traffic with `iptables` | No — static |
| Other token | Send a one-byte UDP status-like response containing ASCII `1` (`0x31`) | No — static |

The bind-shell routine searches the local range **31337–32336** and uses **`nat/PREROUTING`** for port redirection, with a related `INPUT` acceptance rule. In the inspected implementation, that path is particularly tied to details of a TCP activation packet.

### Encrypted shell traffic: RC4

The binary includes identifiable **RC4** components:

| Approximate routine | Function |
|---|---|
| `0x281d` | Key Scheduling Algorithm (KSA) |
| `0x28f9` | Pseudo-Random Generation Algorithm (PRGA) |
| `0x2a69` | Encrypt outgoing session data |
| `0x2aef` | Decrypt incoming session data |

RC4 uses a 256-byte state array, swaps, and XOR with a generated keystream. Separate states are maintained for the two communication directions.

Before encrypted communication, the shell path references the **four-character ASCII handshake**:

~~~text
3458
~~~

The trigger itself is **not wholly encrypted with RC4**: the control token is available to the parser and participates in initialization of the later shell channel.

Neither this handshake nor the encrypted shell stream was observed in the PCAP; their role was inferred from the program's code. RC4 is cryptographically obsolete, but it remains relevant here as an indicator of the malware's communication design.

---

## Controlled execution: REMnux findings

The sample was executed inside an **isolated virtual machine**, with process/syscall tracing and packet capture prepared beforehand. This section records what the lab actually showed, not merely what the code might do.

### Timeline from `strace`

| Time (lab clock) | Evidence | Interpretation |
|---|---|---|
| 14:56:12.438 | `access("/var/run/systemd-private.pid") = -1 ENOENT` | No existing instance marker |
| 14:56:12.478–.563 | `cp`, `chmod` and execution from `/dev/shm/.systemd-runtime` | Staging and self-execution |
| 14:56:12.573 | `utimensat(...) = 0` | Timestamp backdating |
| 14:56:12.575 | `clone(...)` | Fork/daemon-like branch |
| 14:56:12.575 | `openat("/var/run/systemd-private.pid", O_CREAT, ...)` | Creates instance marker |
| 14:56:12.576 | `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)) = 3` | Opens raw packet socket |
| 14:56:12.576 | `setsockopt(... SO_ATTACH_FILTER, {len=30, ...}) = 0` | BPF attachment succeeds |
| 14:56:12.576 | `recvfrom(3, ...` | Enters receive path; no return shown |

The key syscall evidence:

~~~text
14:56:12.576183 socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)) = 3
14:56:12.576404 setsockopt(3, SOL_SOCKET, SO_ATTACH_FILTER,
                   {len=30, filter=0x7fffe6be1890}, 16) = 0
14:56:12.576543 recvfrom(3,
~~~

The successful `setsockopt()` result is the **strongest dynamic confirmation** of the BPF mechanism.

### Memory-backed execution and timestomping

The startup command observed in the trace includes:

~~~sh
/bin/rm -f /dev/shm/.systemd-runtime
/bin/cp ./shadow_monarch /dev/shm/.systemd-runtime
/bin/chmod 755 /dev/shm/.systemd-runtime
/dev/shm/.systemd-runtime --init
/bin/rm -f /dev/shm/.systemd-runtime
~~~

A child later invokes `unlinkat()` successfully for that temporary executable. The copy had also been deliberately backdated using `utimensat()`:

~~~text
2023-11-10 00:00:00 UTC
~~~

The `/var/run/systemd-private.pid` marker is created and later found by the parent process. The captured trace does **not** show a PID being written into it; the term *mutex/lock file* here refers to an **instance-existence marker**, not a conventional locked file descriptor.

### What did the packet capture show?

The saved `shadow_monarch.pcap` was only **116 bytes** and contained **one IPv6 ICMP Router Solicitation** emitted by the laboratory system.

There was **no observed magic packet, reverse connection, bind-shell session or C2 stream**. The absence of such traffic is consistent with a passive listener waiting for a trigger. It does not prove that the listener survived indefinitely.

A post-execution `ss -0ap` check did not show the sample's packet socket; the remaining packet sockets belonged to regular system networking and `tcpdump`. The traced listener may have been terminated by the test's timeout, but the available evidence does not establish its exact shutdown path.

---

## Defense evasion and host artifacts

The ELF contains **ten process-identity strings** that resemble legitimate daemons. The code also uses process-name/environment manipulation; the presence of a string is **not evidence that every name was selected during the lab run**.

~~~text
/usr/lib/systemd/systemd-journald
/usr/lib/systemd/systemd-udevd
/usr/lib/systemd/systemd-logind
/usr/lib/systemd/systemd-resolved
/usr/lib/systemd/systemd-timesyncd
/usr/sbin/rsyslogd -n
/usr/sbin/cron -f
/usr/sbin/sshd -D
/usr/lib/polkit-1/polkitd --no-debug
/usr/sbin/NetworkManager --no-daemon
~~~

Other notable behaviors:

- **Process masquerading:** plausible `systemd`-related identities and `prctl()` usage.
- **File deletion:** removal of the `/dev/shm` copy after launch.
- **Timestomping:** `2023-11-10 00:00:00 UTC` assigned to the temporary executable.
- **Shell history suppression:** `HISTFILE=/dev/null` and `MYSQL_HISTFILE=/dev/null` in the shell setup.
- **Conditional firewall modification:** `iptables` NAT redirection in the bind-shell path.

The time change, temporary-file deletion and BPF installation were visible in the lab. Shell history settings, process disguises and firewall activity were examined in the ELF and were **not all independently triggered**.

---

## Indicators of compromise

These are **sample-specific indicators**, not generic BPFDoor-family infrastructure.

| Category | Indicator | Evidence |
|---|---|---|
| File hash | `41de260cb5518df31ad437f4c0bf0fb2fea848e7648b1911658275da00f2fd16` | Computed SHA-256 |
| Staging executable | `/dev/shm/.systemd-runtime` | `cp` / `execve` / `unlinkat` trace |
| Instance marker | `/var/run/systemd-private.pid` | `access` / `openat` trace |
| Network magic (TCP) | `0x4141`, bytes `41 41` | Reconstructed cBPF |
| Network magic (UDP/ICMP) | `0x8337`, bytes `83 37` | Reconstructed cBPF |
| Pre-RC4 handshake | ASCII `3458` | Static shell path |
| Bind-shell port range | `31337–32336` | Static branch |
| NAT manipulation | `iptables`, `nat/PREROUTING` | Static branch |
| Timestamp | `2023-11-10 00:00:00 UTC` | `utimensat()` trace |
| Network capture behavior | `AF_PACKET` + `SOCK_RAW` + `SO_ATTACH_FILTER` | Successful syscalls |

**No attributable static C2 IPv4 address, domain or attacker-owned endpoint was established.** The destination can be delivered inside an activation message. Magic bytes by themselves are also weak indicators; correlation with the hosting process and its subsequent activity is essential.

## Detection and hunting opportunities

The most useful defense is **behavioral correlation**, rather than matching a single IOC:

1. A root process launches an ELF from `/dev/shm`, then deletes its pathname.
2. Its apparent daemon identity does not align with executable ancestry, file descriptors or service configuration.
3. The process opens an `AF_PACKET` socket and attaches a selective classic BPF filter.
4. Suspicious inbound data is followed by an unexpected outbound TCP connection, new shell, or `iptables` rule.
5. File timestamps are backdated and shell-history variables are redirected.

Read-only inspection examples for a **host under investigation**:

~~~bash
# List packet sockets and their owning processes, where visible
sudo ss -0ap

# Inspect the specific staging and instance-marker paths
sudo ls -la /dev/shm/
sudo ls -l /var/run/systemd-private.pid

# Identify a recovered executable without running it
file /path/to/suspicious_binary
sha256sum /path/to/suspicious_binary
~~~

An empty `ss` output does not rule out compromise: the process may have terminated or deleted its on-disk image, and the point-in-time view can miss transient behavior. Where available, endpoint telemetry for socket creation, `SO_ATTACH_FILTER`, process spawning and firewall changes is more informative.

### MITRE ATT&CK mapping

| Technique | ID | Basis |
|---|---|---|
| Traffic Signaling: Socket Filters | [T1205.002](https://attack.mitre.org/techniques/T1205/002/) | BPF-filtered activation channel |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Service-like process identities |
| Indicator Removal: Timestomp | [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Backdated file timestamps |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Removal of temporary ELF |
| Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Shell path recovered statically |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | RC4 implementation recovered statically |

Some mappings represent **capabilities identified by disassembly**, not events observed in the short lab execution.

---

## Assessment and limitations

The strongest supported conclusion is that **ShadowMonarch is a Linux passive backdoor implementing cBPF-gated packet signaling**. Its bootstrapping behavior and filter attachment were demonstrated in an isolated environment; the message format, tokens, RC4 routines and remote shell capabilities were reconstructed from the executable.

We **did not** demonstrate a successful activation packet, a decrypted live C2 exchange, persistence across reboot or the identity of any attacker. The telecommunications context comes from the Sherlock's scenario. This analysis should not be treated as independent evidence of a real-world intrusion or campaign attribution.

The central lesson is that **absence of a suspicious listening port or outbound beacon does not imply absence of a network backdoor**. In this case, the most revealing evidence lay in the raw socket, its attached classic BPF program and the control flow reached *after* a matching packet.

---

## References

- [MITRE ATT&CK — BPFDoor (S1161)](https://attack.mitre.org/software/S1161/)
- [MITRE ATT&CK — Traffic Signaling: Socket Filters (T1205.002)](https://attack.mitre.org/techniques/T1205/002/)
- [Sandfly Security — BPFDoor: An Evasive Linux Backdoor Technical Analysis](https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis)
- [Sandfly Security — BPFDoor Detection, Analysis and Hunting Tactics](https://sandflysecurity.com/blog/bpfdoor-detection-analysis-and-hunting-tactics-on-linux)

**Primary evidence:** `shadow_monarch` (SHA-256 above), isolated REMnux `strace` records and the laboratory `tcpdump` result. External reports provide technique context; their unrelated IOCs have not been attributed to this sample.

> **Safety:** The live binary, original ZIP and execution artifacts are intentionally not published here. All dynamic testing was restricted to an isolated malware-analysis VM.

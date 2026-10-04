# Findings and challenge answers

## Challenge answers

| Question | Answer |
|---|---|
| Hidden kernel module | `singularity` |
| Kernel taint flags, alphabetical | `OOT_MODULE,UNSIGNED_MODULE` |
| Rootkit load time, seconds since boot | `2490.473832` |
| PID that loaded the rootkit | `2669` |
| Hooked kernel tracepoint | `sched_process_fork` |
| C2 IP address | `192.168.200.164` |
| C2 port | `8081` |
| Compromised bash PIDs | `2693,2695,2698` |
| Number of ftrace hooks | `82` |
| Function hooked to hide IPv4 connections | `tcp4_seq_show` |
| Number of hooked `getdents` variants | `5` |
| Function hooked for the ICMP covert channel | `icmp_rcv` |
| Centralized callback address | `0xffffc0b3aac0` |
| Suspicious environment-variable value used in privilege escalation | `access` |

---

## Indicators and artifacts

| Type | Value | Context |
|---|---|---|
| Kernel module | `singularity` | Hidden rootkit module |
| Module structure | `0xffffc0b42640` | Volatility hidden-module result |
| Module code base | `0xffffc0b35000` | Address reported by Volatility |
| Module size | `0x19000` | 102,400 bytes |
| ftrace callback | `0xffffc0b3aac0` | Shared callback for rootkit hooks |
| Tracepoint | `sched_process_fork` | Rootkit tracepoint registration |
| C2 IP | `192.168.200.164` | Remote endpoint |
| C2 port | `8081/TCP` | Remote endpoint |
| Compromised process | `bash` PID `2693` | C2-connected shell |
| Compromised process | `bash` PID `2695` | C2-connected shell |
| Compromised process | `bash` PID `2698` | C2-connected shell |
| Environment artifact | `OPERATOR=access` | Privilege-escalation sequence |
| Command artifact | `kill -59 $$` | Observed immediately after spawning the marked shell |
| Source artifact | `/root/Singularity/modules/become_root.c` | Recovered from memory strings |
| Source artifact | `/root/Singularity/modules/hidden_pids.c` | Recovered from memory strings |
| Source artifact | `/root/Singularity/modules/icmp.c` | Recovered from memory strings |

---

## Capability mapping

| Capability | Evidence |
|---|---|
| Module hiding | Hidden `singularity` module and `hide_module.c` string |
| Process hiding | `getdents` hooks, `hidden_pids.c`, `add_hidden_pid` |
| Network hiding | `tcp4_seq_show` and `tcp6_seq_show` hooks |
| ICMP covert channel | `icmp_rcv` hook and `icmp.c` artifacts |
| Privilege escalation | `OPERATOR=access`, `kill -59 $$`, root child shell, `become_root.c` |
| Process-control backdoor | Hooked `__x64_sys_kill` / `hook_kill` artifact |
| File and directory hiding | `getdents`, stat/lstat/statx/openat hooks |
| BPF interception | x86 and compat BPF syscall hooks, `bpf_hook.c` |
| Module-load interception | `init_module` / `finit_module` hooks |
| Data interception | read/write, vectored I/O, sendfile, splice and copy paths |

---

## Confidence notes

The hidden module, hook registrations, C2 sockets, shell PIDs, load time, tracepoint, environment value, and bash history are directly supported by memory-forensics artifacts.

The privilege-escalation mechanism is strongly correlated with `OPERATOR=access`, `kill -59 $$`, `hook_kill`, and `become_root.c`, but the exact source-level implementation was not completely reconstructed from the carved module.

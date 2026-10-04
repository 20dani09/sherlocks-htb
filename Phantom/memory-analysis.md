# Memory analysis

## 1. Kernel identification

The image was first validated against the supplied Linux symbols:

```bash
/usr/local/bin/vol3 -f dump_srv.mem banners.Banners
```

The recovered banner identified Ubuntu kernel `6.8.0-87-generic`, matching `Ubuntu_6.8.0-87-generic.json`.

---

## 2. Process review

Active processes were enumerated with:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.pslist.PsList
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.psscan.PsScan
```

Notable findings included three kernel-thread-like tasks named `psimon`, several root-owned shells around the compromise window, and the `avml` process used to acquire the memory image.

Comparing `PsList` and `PsScan` did not provide clear evidence that an active process had been unlinked from the normal process list.

---

## 3. Hidden module discovery

A normal module-consistency check returned only a VMware/vsock-related discrepancy:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.check_modules.Check_modules
```

The dedicated hidden-module plugin revealed the actual rootkit:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.malware.hidden_modules.Hidden_modules
```

Result:

```text
0xffffc0b42640 singularity 0x19000 OOT_MODULE,UNSIGNED_MODULE
```

The module was both out of tree and unsigned.

---

## 4. Module load evidence

Kernel messages were inspected using:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.kmsg.Kmsg | grep -i -E 'singularity|taint|module|psimon'
```

Relevant records:

```text
kern warn   2490.473832 Task(2669) singularity: loading out-of-tree module taints kernel.
kern notice 2490.473840 Task(2669) singularity: module verification failed: signature and/or required key missing - tainting kernel
```

This establishes:

- Load time: **2490.473832 seconds since boot**
- Loader PID: **2669**

---

## 5. Syscall table versus ftrace

The syscall table was checked with:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.malware.check_syscall.Check_syscall
```

Key entries still resolved to normal kernel handlers, including `connect` and the `getdents` family. This is important because the rootkit did not rely on the classic technique of directly replacing syscall-table pointers.

The ftrace state told a different story:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.tracing.ftrace.CheckFtrace
```

Counting entries belonging to the rootkit:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.tracing.ftrace.CheckFtrace | grep -i singularity | wc -l
```

Result:

```text
82
```

All of these hooks referenced module `singularity` and a centralized callback at:

`0xffffc0b3aac0`

Important coverage included network presentation, directory enumeration, process control, BPF, file I/O, module loading, and data movement.

---

## 6. Tracepoint hook

Tracepoints were checked independently:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.tracing.tracepoints.CheckTracepoints | grep -i singularity
```

The rootkit was registered on:

`sched_process_fork`

This is separate from the 82 ftrace entries.

---

## 7. C2 reconstruction

Socket state was recovered using:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.sockstat.Sockstat
```

Three `bash` processes had file descriptors 0, 1, and 2 attached to established TCP sessions toward the same endpoint:

```text
PID 2693  192.168.200.177:48440 -> 192.168.200.164:8081
PID 2695  192.168.200.177:48444 -> 192.168.200.164:8081
PID 2698  192.168.200.177:48454 -> 192.168.200.164:8081
```

This is strong evidence of remote interactive shells connected to:

`192.168.200.164:8081/TCP`

`PsAux` further showed the compromised shells with the argument `singularity`.

---

## 8. Privilege-escalation sequence

Bash history:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.bash.Bash
```

Recovered sequence:

```text
2025-11-19 17:40:57 UTC  clear
2025-11-19 17:41:02 UTC  OPERATOR=access bash
2025-11-19 17:41:06 UTC  kill -59 $$
2025-11-19 17:41:08 UTC  internal_fifos
2025-11-19 17:41:08 UTC  ps aufwx
```

The resulting shell, PID `2792`, was root-owned according to the process credentials.

Its environment was then inspected:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . linux.envars.Envars --pid 2792
```

Important values:

```text
OPERATOR=access
SHELL=/bin/bash
PWD=/home/workstation
LOGNAME=workstation
HOME=/home/workstation
USER=workstation
SSH_CONNECTION=192.168.200.1 63600 192.168.200.177 22
```

The mismatch between root process credentials and the inherited `workstation` environment strongly corroborates privilege escalation rather than a normal root login.

---

## 9. Targeted rootkit strings

Because ELF reconstruction failed, strings were used only as targeted supporting evidence:

```bash
strings -a dump_srv.mem | grep -i 'Singularity/modules' | sort -u
```

Recovered source-path artifacts included:

```text
/root/Singularity/modules/become_root.c
/root/Singularity/modules/bpf_hook.c
/root/Singularity/modules/clear_taint_dmesg.c
/root/Singularity/modules/hidden_pids.c
/root/Singularity/modules/hide_module.c
/root/Singularity/modules/hiding_directory.c
/root/Singularity/modules/hiding_stat.c
/root/Singularity/modules/open.c
/root/Singularity/modules/icmp.c
```

Additional strings exposed `hook_kill`, `add_hidden_pid`, `is_hidden_pid`, `become_root_init`, and `become_root_exit`.

These artifacts align closely with the capabilities independently observed through Volatility.

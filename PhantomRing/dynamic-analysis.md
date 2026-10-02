# PhantomRing — Dynamic Analysis

## Lab setup

Dynamic analysis was performed inside an isolated REMnux VM.

The malware expects:

```text
192.168.56.1:4445/TCP
```

To keep all traffic inside the VM, the C2 address was assigned to loopback:

```bash
sudo ip addr add 192.168.56.1/32 dev lo
```

The VM had no default route during execution.

A Netcat listener emulated the C2:

```bash
nc -l -p 4445 -s 192.168.56.1
```

Traffic was observed with:

```bash
sudo tcpdump -i lo -nn -A tcp port 4445
```

---

## Dependency

The sample requires:

```text
liburing.so.2
```

After installing `liburing2`, `ldd` resolved:

```text
liburing.so.2 => /lib/x86_64-linux-gnu/liburing.so.2
```

---

## C2 connection

Execution:

```bash
./agent
```

Observed:

```text
[+] Connected to 192.168.56.1:4445
```

`tcpdump` confirmed the TCP handshake on loopback.

---

## Command validation

### me

C2 command:

```text
me
```

Observed:

```text
PID: 3587
TTY: /dev/pts/1
```

### users

Observed active sessions:

```text
Logged users:
remnux   seat0
remnux   tty2
remnux   pts/3
```

This matches the static finding that the malware parses `/var/run/utmp`.

### ps

The agent returned a full process listing directly from procfs. The output included the lab processes:

```text
3561    nc
3576    tcpdump
3587    agent
```

### ss

The agent returned TCP state information including its own C2 session:

```text
192.168.56.1:4445      192.168.56.1:50958     1     1000
192.168.56.1:50958     192.168.56.1:4445      1     1000
```

The TCP state value `1` corresponds to ESTABLISHED.

### netstat

Returned the same output as `ss`, confirming it is an alias.

### get

Command:

```text
get /etc/hostname
```

Response:

```text
remnux
```

This validates local file exfiltration from the victim to the C2.

### privesc

The command returned SUID binaries including:

```text
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/chfn
/usr/bin/sg
/usr/bin/mount
/usr/bin/fusermount3
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/vmware-user
/usr/bin/pkexec
/usr/bin/vmware-user-suid-wrapper
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/sudoedit
```

### kick

Without an argument:

```text
Active pts sessions:
pts/3
pts/2
pts/0
pts/1
```

The destructive form, `kick <pts>`, was not used.

### recv

A 6-byte test file was transferred from the C2 to the victim:

```text
recv /tmp/agent_test.txt 6
hello
```

Validation:

```text
00000000: 68 65 6c 6c 6f 0a
```

The bytes correspond to `hello\n`.

### exit

Observed:

```text
Agent disconnecting and exiting
```

Afterward:

```text
agent stopped
```

The executable remained on disk.

### sdestruct

A copy of the sample was created first to preserve the original.

Command:

```text
sdestruct
```

Response:

```text
Agent will self-destruct
```

Post-execution validation:

```text
agent_sd stopped
ls: cannot access './agent_sd': No such file or directory
```

This confirms that the handler both terminates the process and removes its own executable.

---

## Not executed

`killbpf` was intentionally not executed because the reversed code can modify tracing state, remove BPF objects, and kill processes.

The static analysis was sufficient to characterize this functionality without unnecessarily damaging the analysis VM.

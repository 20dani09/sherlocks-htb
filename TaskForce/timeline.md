# Timeline

All timestamps below are in **UTC**.

| Time | Activity | Evidence |
|---|---|---|
| 2026-06-05 | Legitimate scheduled-task baseline created across systems, including SQLConnectivityCheck | PowerShell 4103/4104 |
| 2026-06-09 12:39:16.190 | Inbound RDP connection reaches ALLIANCE-WS07 from 192.168.72.131 | Sysmon Event 3 |
| 2026-06-09 12:41:05.138 | Environment for john.shepard is initialized | Sysmon Event 13 |
| 2026-06-09 12:41:09.833 | RDP session registry values created: SESSIONNAME=RDP-Tcp#0, CLIENTNAME=kali | Sysmon Event 13 |
| 2026-06-09 12:41:09 | First malicious login time used by the challenge | Session reconstruction |
| 2026-06-09 12:41:10.804 | First visible process associated with john.shepard / Logon ID 0x7B9417 | Sysmon Event 1 |
| 2026-06-09 12:41:12.399 | rdpclip.exe active under john.shepard | Sysmon Event 7 |
| 2026-06-09 12:41:17 | Interactive user environment continues initialization | Security 4688 / Sysmon |
| 2026-06-09 12:55:13.973 | PowerShell script block downloads, extracts, and launches SoftPerfect Network Scanner | PowerShell 4104 |
| 2026-06-09 12:55:26-27 | netscan.exe extracted under C:\Users\Public\SoftPerfect\x86_64 | Sysmon file events / PowerShell |
| 2026-06-09 12:55:28.050 | netscan.exe launched by PowerShell in Logon ID 0x7B9417 | Security 4688 |
| 2026-06-09 12:55:28.050 | Sysmon confirms netscan.exe, john.shepard, Terminal Session ID 2 and Logon ID 0x7B9417 | Sysmon Event 1 |
| 2026-06-09 12:55:48+ | Network scanner begins DNS, Internet, and internal-network activity | Sysmon Event 3/22 |
| 2026-06-09 13:21:10.476 | Defender exclusion added for process name SQLBackup.exe | Defender Event 5007 |
| 2026-06-09 22:37:53.015 | C:\Users\Public\Pictures\SQLBackup.exe executes on ALLIANCE-CENTRAL | Security 4688 |
| 2026-06-09 22:37:53.280 | SQLBackup.exe spawns another SQLBackup.exe process | Security 4688 |
| 2026-06-09 22:37:53.290 | Windows Error Reporting starts for the original process | Process telemetry |
| 2026-06-09 22:37:53.333 | SQLBackup.exe crashes in ntdll.dll, exception 0xc0000374 | Application Event 1000 |
| 2026-06-09 22:37:55.055 | Windows Error Reporting archives the crash | Application Event 1001 |
| 2026-06-15 14:10:24.329 | Task Scheduler records failure for SQLConnectvityCheck because the configured user was not logged on | Task Scheduler Event 332 |
| 2026-06-15 15:06:41.238 | A second Task Scheduler Event 332 is recorded for the same typo task | Task Scheduler Event 332 |

---

## Reconstructed sequence

~~~text
kali / 192.168.72.131
        |
        | RDP
        v
ALLIANCE-WS07 / 192.168.72.101:3389
        |
        +--> john.shepard
        |     LogonId: 0x7B9417
        |     TerminalSessionId: 2
        |
        +--> PowerShell
                |
                +--> download netscan_portable.zip
                +--> Expand-Archive
                +--> netscan.exe
                        |
                        +--> network reconnaissance

Later activity
        |
        +--> Defender exclusion: SQLBackup.exe
        |
        +--> C:\Users\Public\Pictures\SQLBackup.exe
        |       |
        |       +--> child SQLBackup.exe
        |       +--> crash / WER
        |
        +--> persistence artifact:
                SQLConnectvityCheck
~~~

---

## Interpretation

The timeline supports a coherent intrusion path:

- An external or attacker-controlled RDP client identified as kali connected to ALLIANCE-WS07.
- The attacker used the john.shepard account.
- The session performed active network reconnaissance with SoftPerfect Network Scanner.
- Subsequent activity included Defender tampering and execution of SQLBackup.exe on ALLIANCE-CENTRAL.
- A look-alike scheduled task with a one-character naming error was later observed as a persistence artifact.

The dataset does not provide every expected authentication event, so the session origin was established through corroborating Sysmon and registry telemetry instead.

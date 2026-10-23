# Kraken — Indicators of Compromise and Detection Notes

## 1. File hashes

These hashes were recalculated from the artifacts recovered locally or reconstructed **statically** from the supplied encrypted content.

| Artifact | Size (bytes) | SHA-1 | SHA-256 |
|---|---:|---|---|
| <code>Conf.js</code> (inside <code>Art-.zip</code>) | 114,592 | <code>40e4ff24520198ae4518f4bb6d3c07d58892d439</code> | <code>0e5c2dc881698eddca82990a30bb2f734065b2eb9ea329b03fbf454e43a254e8</code> |
| <code>temp_993805.bat</code> / <code>dwm.bat</code> / <code>5c74.bat</code> | 103,413 | <code>e0d6ec7cfe1882589507132d7b50669710534034</code> | <code>bd2cc2f1f25b5f520a87068475247dd5611ab9f199ed3264983d720e016acf66</code> |
| Auxiliary .NET PE (stage 2a) | 4,096 | <code>339e27243df24f2b8979e78711e396698f4f47cc</code> | <code>8fa3103bcd5d7d097dddcd0b1d56614b9787a019cfad2af0b5e24cd7f4b49e7a</code> |
| Stage-2 .NET PE containing resource | 31,232 | <code>0c4236fd5a8b2cd632da0c1e06444e0a95bb7cd3</code> | <code>3d8c31a68e3fab61212af7ebb3024c5ab079cd205a9297333824f342113b6058</code> |
| Final RAT .NET PE | 49,664 | <code>052c0687f023564a3c31fb652bea3405341272cb</code> | <code>9d86ea12e0643cd79f6f97202716d6e7b2a0f2dc81b9255719bb5ca7aaeebd12</code> |

The byte-identical batch variants all share the same hashes.

## 2. On-disk artifacts (victim)

~~~text
C:\Users\Administrator\AppData\Local\Temp\temp_993805.bat
C:\Users\Administrator\dwm.bat
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\5c74.bat
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\Conf.js.lnk
~~~

Other contextual evidence:

~~~text
...\Windows\Prefetch\WSCRIPT.EXE-3FF4D889.pf
...\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
...\AppData\Local\Temp\vmware-Administrator\VMwareDnD\4e33d455\Art-.zip
~~~

**Note:** <code>temp_993805.bat</code> and <code>5c74.bat</code> are incident-specific random names. Hunt the **pattern and execution chain**, not only these exact basenames.

## 3. Network indicators

| Indicator | Value | Provenance |
|---|---|---|
| C2 hostname | <code>apostlejob3.duckdns.org</code> | Local static final PE; external sandbox |
| C2 port | <code>2468/TCP</code> | Local static final PE; external sandbox |
| C2 IP | <code>107.172.232.84</code> | **External ANY.RUN Connections/DNS on exact recovered SHA-256** |
| Full sandbox endpoint | <code>107.172.232.84:2468</code> | External exact-hash sandbox, **not locally proven** |

External observation: [ANY.RUN sample report](https://any.run/report/9d86ea12e0643cd79f6f97202716d6e7b2a0f2dc81b9255719bb5ca7aaeebd12/e51a4b2f-a59e-490b-b90f-92abd400e6c5).

The domain uses DuckDNS; current DNS resolutions should not be treated as evidence of what resolved at the victim's event time.

## 4. Strings / behavior indicators

~~~text
MasonClient1.exe
NeptuneRAT V5.3
MasonRAT
MasonGroup
MasonUSB.exe
Antarctica.Territories
System.Threading.Mutex
Assembly.Load
AmsiInitialize
EtwEventWrite
VirtualProtect
Invoke-SystemMaintenance
~~~

Embedded managed-resource name:

~~~text
xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe
~~~

Full User-Agent examples are documented in [malware-analysis.md](./malware-analysis.md). User-Agents and innocuous Windows APIs are **weak standalone indicators** and should not trigger high-severity alerts without context.

## 5. MITRE ATT&CK mapping (evidence-aware)

| Technique | ID | Supporting behavior |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User launches <code>Conf.js</code> through Windows Script Host |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | JS creates and runs a BAT under <code>cmd.exe</code> |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Hidden PowerShell and decoded script execution |
| Boot or Logon Autostart Execution: Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | <code>5c74.bat</code> in the user's Startup folder |
| Impair Defenses | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Code attempting to tamper with AMSI and ETW in memory |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Batch obfuscation, Base64 reconstruction, AES/GZip unpacking |
| Reflective Code Loading | [T1620](https://attack.mitre.org/techniques/T1620/) | <code>Assembly.Load(byte[])</code> of managed assemblies |
| Dynamic Resolution | [T1637](https://attack.mitre.org/techniques/T1637/) | Dynamic-DNS hostname used as configured C2 |
| Application Layer Protocol / C2 | **Configuration only** | Host and port recovered; victim-side connection not verified |

**Caution:** the final row is intentionally not assigned a specific ATT&CK protocol subtechnique because the provided host evidence does not identify the full application-layer C2 protocol.

## 6. High-value threat hunting

Prioritize behavioral correlations:

1. <code>wscript.exe</code> launching <code>cmd.exe</code>, especially when the parent script originated in Downloads or an extracted archive.
2. A newly created <code>%TEMP%\temp_*.bat</code> shortly followed by a file in the user's Startup folder.
3. Hidden PowerShell using <code>-noprofile</code>, <code>-windowstyle hidden</code>, <code>-ep bypass</code>.
4. PowerShell use of <code>Assembly.Load(byte[])</code> together with AES-CBC, GZip or <code>Invoke-Expression</code>.
5. Memory writes/permission changes involving AMSI code paths or <code>EtwEventWrite</code>.
6. DNS/egress to the case hostname/IP:port, with historical context and process attribution.

## 7. Reliability notes

The RAT family name is not established solely by an embedded string. External scanner labels include XWorm, AsyncRAT and Violet; the binary also carries <code>NeptuneRAT V5.3</code>. Report these as **indicators / scanner classifications**, not independent proof of an exact lineage.

The recovered <code>.bin</code> files produced during static analysis are analyst-generated copies, **not additional disk-dropping events on the victim**.

No malicious payloads are hosted in this repository.

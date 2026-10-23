# Kraken — HTB Sherlock

## Overview

**Kraken** is a Windows malware-analysis and digital-forensics Sherlock concerning an early-stage infection by an obfuscated, multi-stage .NET remote-access trojan (RAT). The incident begins when the Administrator user executes <code>Conf.js</code>, a Windows Script Host JavaScript file. It creates a temporary batch launcher, establishes startup-folder persistence, bypasses security instrumentation in memory, and decrypts multiple .NET assemblies. The final embedded PE contains RAT configuration and a dynamic-DNS C2 endpoint.

This write-up combines **logical-image forensics (AD1), Prefetch, Recent LNK artifacts, PowerShell logs, static JavaScript/batch deobfuscation, .NET resource extraction, cryptographic unpacking and hash-based sandbox enrichment**.

The supplied case states that the SOC contained the incident before full C2/post-exploitation activity. Our evidence confirms execution and persistence artifacts but **does not independently prove exfiltration or a completed C2 connection on the compromised host**.

## Evidence and setup

| Item | Detail |
|---|---|
| Supplied archive | <code>Kraken.zip</code> (password supplied with the challenge: <code>hacktheblue</code>) |
| Forensic image | <code>Evidence.ad1</code> (AccessData logical image) |
| Image size | 296,383,238 bytes |
| Image SHA-256 | <code>0107fe6943d057890c32fd0a97b75785d626588c32469bcb44bb3eeb2b8d775a</code> |
| Relevant Windows user | <code>Administrator</code> |
| Incident date | **2025-06-13** |
| Time standard used | **UTC** |
| Final payload format | .NET PE32 executable, 49,664 bytes |
| C2 configuration | <code>apostlejob3.duckdns.org:2468</code> |
| Sandbox-observed endpoint | <code>107.172.232.84:2468</code> (external exact-hash enrichment) |

No original malware binaries, decoded PowerShell payloads, credential material or raw forensic image are committed to this repository.

## Reconstructed infection chain

~~~text
User opens Conf.js (Windows Script Host / wscript.exe)
  |
  +-- writes %TEMP%\temp_993805.bat
        |
        +-- starts obfuscated batch logic
        +-- copies itself to C:\Users\Administrator\dwm.bat
        +-- leaves 5c74.bat in the user's Startup folder
        +-- launches hidden PowerShell with encoded command
              |
              +-- decodes another PowerShell script from batch content
              +-- attempts AMSI / ETW in-memory patching
              +-- AES-CBC decrypts two base64 blobs; GZip decompresses
                    |
                    +-- Auxiliary .NET PE (4,096 bytes)
                    +-- Stage-2 .NET PE (31,232 bytes)
                          |
                          +-- embedded .NET resource:
                          |   xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe
                          +-- AES-CBC + GZip
                                |
                                +-- Final RAT PE (49,664 bytes)
                                    Internal filename: MasonClient1.exe
                                    Embedded string: NeptuneRAT V5.3
                                    C2: apostlejob3.duckdns.org:2468
~~~

The first batch, Startup batch and <code>dwm.bat</code> are identical by SHA-256. The PE files are recovered by **static decryption**; their existence as standalone disk files on the victim is not inferred from our analyst-created output files.

## High-confidence findings

| Finding | Evidence |
|---|---|
| User execution | Compressed <code>WSCRIPT.EXE-3FF4D889.pf</code>, execution time **2025-06-13 14:43:27.197376 UTC**; reference to <code>Conf.js</code> |
| First file dropped | <code>temp_993805.bat</code> in the user Temp folder |
| In-memory defense evasion | AMSI-related patch bytes <code>B8 00 00 00 00 C3</code> and ETW patching routine in decoded PowerShell |
| Batch loader copy | <code>C:\Users\Administrator\dwm.bat</code> |
| Persistence | <code>C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\5c74.bat</code> |
| Auxiliary PE SHA-1 | <code>339e27243df24f2b8979e78711e396698f4f47cc</code> |
| Final RAT SHA-1 | <code>052c0687f023564a3c31fb652bea3405341272cb</code> |
| Final RAT SHA-256 | <code>9d86ea12e0643cd79f6f97202716d6e7b2a0f2dc81b9255719bb5ca7aaeebd12</code> |
| Mutex-holding field | <code>Antarctica.Territories</code> (<code>System.Threading.Mutex</code>) |
| Sandbox C2 | <code>107.172.232.84:2468</code> — **not proven in local AD1 telemetry** |

## Repository contents

- [Forensic timeline](./timeline.md) — all important timestamps and provenance.
- [Malware reverse engineering](./malware-analysis.md) — original artifacts, loader logic, two AES layers, .NET reversing and safe reproduction.
- [Network and C2 assessment](./network-analysis.md) — static configuration vs. separately observed sandbox connections.
- [Indicators and detection](./iocs.md) — hashes, paths, infrastructure, MITRE ATT&CK and hunting ideas.
- [Challenge questions and evidence](./findings.md) — all **12 answers**, plus how each was established.
- [Static recovery helper](./tools/recover_payloads.py) — offline AES/GZip extraction of the three .NET PEs from an already extracted batch. **Never executes any recovered file.**

## Confidence and scope

**Direct local evidence:** user execution time, dropped files, Startup persistence, identical batch contents, decoded scripts, cryptographic keys, recovered .NET PE hashes, resource name, mobile User-Agent, and RAT configuration.

**Independent external enrichment:** a public ANY.RUN report on the *exact recovered SHA-256* shows the final sample communicating with <code>107.172.232.84:2468</code>; this is a different sandbox run, not a packet capture from the victim.

**Not established locally:** C2 handshake, successful data exfiltration, which RAT commands were executed, the exact time of SOC intervention or the actual success of all in-memory patches.

The malicious sample has been associated by different scanners with several overlapping families (NeptuneRAT / XWorm / AsyncRAT). Strings and vendor classifications are treated as **attribution clues**, not proof of a unique lineage.

> **Lab safety:** Perform extraction and reversing offline in a controlled lab. Treat all recovered PE files and scripts as malware. Do not execute or upload them to the repository.

# CAMouflage

## Overview

**CAMouflage** is a Windows malware-analysis and DFIR Sherlock focused on a compromise initiated through a cracked Mastercam installer.

The investigation combines browser history, Prefetch, BAM, dropped batch content, AutoIt payload reconstruction, static analysis, and external threat-intelligence pivoting to reconstruct the execution chain from the initial download to the final information-stealer payload.

The most valuable artifacts were:

- Microsoft Edge `History`
- Windows Prefetch
- `SYSTEM` hive / BAM
- `C:\Users\Administrator\AppData\Local\Temp\Mysql.wp5`
- `Play.wp5`
- The reconstructed AutoIt payload file `K`
- The renamed AutoIt interpreter `Moscow.com`

---

## Initial access

The user searched for a cracked copy of Mastercam and followed the following browser chain:

```text
Bing
  -> khophanmem.vn/mastercam-x9/
  -> fancli.com/2wAHI6/
  -> media.cloud839v1.cfd
  -> Download Mastercam X9 Full Crack Pc.7z
```

Relevant Edge activity:

| Time (UTC) | Activity |
|---|---|
| 2025-06-21 16:37:17 | Search: `mastercam download for free` |
| 2025-06-21 16:38:02 | Search: `mastercam x9 full crack` |
| 2025-06-21 16:38:41 | Visit: `khophanmem.vn/mastercam-x9/` |
| 2025-06-21 16:40:44 | Search containing `"fancli"` |
| 2025-06-21 16:41:07 | Visit: `fancli.com/2wAHI6/` |
| 2025-06-21 16:41:22 | Download written as `Download Mastercam X9 Full Crack Pc.7z` |

The browser download source ultimately pointed to:

```text
https://media.cloud839v1.cfd/Download+Mastercam+X9+Full+Crack+Pc.zip
```

---

## Execution chain

Prefetch and batch analysis reconstruct the following chain:

```text
7zG.exe
  -> download mastercam x9 full crack pc.exe
      -> cmd.exe
          -> Mysql.wp5 / Mysql.wp5.bat
              -> extrac32.exe /Y Play.wp5 *.*
              -> reconstruct Moscow.com
              -> reconstruct K
              -> Moscow.com K
                  -> AutoIt loader
                      -> RC4 decrypt
                      -> LZNT1 decompress
                      -> stage2 PE32
```

The cracked installer first executed at:

```text
2025-06-21 18:34:19.262602 UTC
```

BAM recorded the installer at:

```text
2025-06-21 18:36:52Z
\Device\HarddiskVolume3\Users\Administrator\Downloads\download mastercam x9 full crack pc.exe
```

For the Sherlock, this is the expected installer-termination timestamp. Strictly speaking, BAM is execution evidence and not a direct equivalent of a Security 4689 process-exit event.

---

## Dropped and reconstructed components

### Mysql.wp5

The first dropped file identified after installation was:

```text
C:\Users\Administrator\AppData\Local\Temp\Mysql.wp5
```

After deobfuscation, the batch logic showed:

- Security-product checks.
- Creation of temporary directory `448887`.
- Extraction of `Play.wp5` with `extrac32.exe`.
- Reconstruction of `Moscow.com`.
- Reconstruction of the payload file `K`.
- Execution of `Moscow.com K`.

The extraction command was:

```bat
extrac32 /Y Play.wp5 *.*
```

### AV / EDR checks

The relevant AV/EDR branch searched for six product-related process/service strings:

```text
bdservicehost
SophosHealth
AvastUI
AVGUI
nsWscSvc
ekrn
```

The challenge answer is therefore **6**.

### Moscow.com

The batch launches:

```bat
start Moscow.com K
```

Static strings and the batch's alternate execution path identify `Moscow.com` as a renamed **AutoIt3.exe** runtime.

SHA-256:

```text
1300262a9d6bb6fcbefc0d299cce194435790e70b9c7b4a651e202e90a32fd49
```

### K

The batch reconstructs `K` from multiple `.wp5` fragments.

SHA-256:

```text
2b3d1561b9ae7fa2bd3f09dee28a327b5647a908113945cd2a943134822d18d0
```

An AutoIt compiled-script structure begins inside this file and was extracted for further reversing.

---

## Final payload reconstruction

The AutoIt script contained an encrypted payload assembled in a large hexadecimal variable.

The analysis recovered:

- Encrypted blob size: **221249 bytes**
- RC4 key:

```text
71301344071371155438579663303386877993
```

The RC4 output was an LZNT1 stream. After decompression, the resulting payload was:

| Field | Value |
|---|---|
| Type | PE32 GUI executable |
| Size | 351744 bytes |
| SHA-256 | `268b44beaa84147c2f8bf78a1f5527144864f1da6d0833d71298bb2716d3df5d` |
| Local AV classification | `Trojan:Win32/LummaStealer.GPT!MTB` |

Static imports included APIs for:

- Clipboard access.
- Screen capture.
- COM interaction.
- Process/thread execution.
- Shell-folder access.

The loader also contains behavior consistent with restoring a clean `ntdll.dll` mapping and executing the final PE in memory.

---

## C2 identification

The C2 domain did **not** appear in clear text in the retained KAPE artifacts or in the reconstructed stage-2 PE.

The C2 was recovered by pivoting on the SHA-256 of the reconstructed `K` file in VirusTotal Community. The comment associated with that exact sample states that the file loaded by the AutoIt script makes a C2 connection to:

```text
crowfza.xyz
```

The related hash in that community pivot is the exact SHA-256 of our reconstructed `Moscow.com`, linking the threat-intelligence result back to the local evidence.

This distinction matters: the domain is **externally corroborated from the exact sample hash**, not directly recovered from the KAPE network telemetry.

---

## Repository contents

- [Timeline](./timeline.md)
- [Malware analysis](./malware-analysis.md)
- [Indicators](./iocs.md)
- [Findings and challenge answers](./findings.md)

---

## Scope note

This write-up separates conclusions derived directly from the supplied forensic artifacts from external threat-intelligence enrichment. No network behavior is presented as locally observed unless the available evidence supports it.

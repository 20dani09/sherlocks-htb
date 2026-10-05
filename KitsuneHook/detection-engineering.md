# KitsuneHook — Detection Engineering

## Overview

The strongest defensive value in RevivalStone comes from **behavioral chaining**.

Many individual artifacts can be changed by an operator, but the campaign requires several uncommon actions to occur together:

- exploitation of a public-facing application,
- web-shell activity,
- unusual service transitions,
- DLL hijacking,
- creation of a suspicious DAT container,
- temporary kernel-driver deployment,
- NDIS registration,
- and user/kernel communication through unusual device objects.

This file translates those public findings into practical hunting ideas.

> The example rules below are original defensive examples derived from public technical indicators. They are not copies of vendor production rules and require validation before deployment.

---

## High-value artifacts

| Artifact | Relevance |
|---|---|
| `SessionEnv` | Service abused to begin the malware execution chain |
| `TSMSISrv.dll` | Malicious DLL loaded through SessionEnv-related behavior |
| `mresgui.dll` | Winnti Loader / PRIVATELOG in RevivalStone |
| `C:\Windows\Installer\dmdwv.dat` | Encrypted payload container |
| `amonitor.sys` | Temporary Winnti rootkit installer |
| `AmdK8` | Legitimate service temporarily repointed during rootkit deployment |
| `IPSecMiniPort` | Dummy NDIS protocol registered by the rootkit |
| `\Device\Beep` | Device object used for user/kernel communication |
| `\Device\Null` | Alternate device object used by the rootkit |
| `0x15E030` / `0x156008` | Rootkit communication control codes |

---

## Windows event hunting

### SessionEnv state changes

LAC recommends reviewing unexpected **SessionEnv** service starts and stops.

Relevant System events may include:

```text
Event ID 7036
Event ID 7040
```

A useful hunting pattern is:

```text
SessionEnv starts or changes unexpectedly
        +
svchost.exe loads TSMSISrv.dll
        +
subsequent Winnti-related file activity
```

The correlation is much stronger than any one event in isolation.

---

## Code-integrity telemetry

On newer Windows Server versions, unsigned DLL loading by `svchost.exe` may generate Security-Mitigation telemetry.

LAC highlights:

```text
Event ID 11
Event ID 12
```

These events become particularly interesting when the referenced module is:

```text
TSMSISrv.dll
```

or when the load occurs close to a SessionEnv service transition.

---

## Filesystem hunting

### DAT payload

Look for unexpected DAT files under:

```text
C:\Windows\Installer\
```

with special attention to:

```text
dmdwv.dat
```

### Rootkit installer

High-confidence artifact:

```text
C:\Windows\System32\drivers\amonitor.sys
```

Because the installer may be removed after use, endpoint telemetry that records **historical file creation and deletion** is more valuable than point-in-time filesystem inspection.

### Temporary DLL naming

LAC observed temporary DLL copies using a pattern similar to:

```text
_[A-Za-z]{5,9}.dll
```

under System32-related activity.

That pattern by itself is not sufficient for detection, but it can be useful when correlated with suspicious module loads and immediate deletion.

---

## Registry hunting

A strong rootkit-related indicator is registration of:

```text
IPSECMINIPORT
```

under the Windows services / networking configuration.

A generic hunting concept:

```text
Registry path contains:
\Services\IPSECMINIPORT
```

Correlate the event with:

- driver creation,
- AmdK8 service modification,
- SessionEnv activity,
- and Winnti-related file writes.

---

## Service modification hunting

The rootkit deployment chain temporarily modifies **AmdK8**.

Look for:

1. AmdK8 configuration change.
2. Image path pointing to an unusual driver.
3. Service start.
4. Restoration of the original path.
5. Deletion or unloading of the temporary driver.

A short-lived malicious service configuration can be easy to miss if monitoring only final state.

---

## Memory forensics pivots

LAC recommends memory-oriented validation when endpoint telemetry is incomplete.

Useful targets include:

```text
amonitor.sys
IPSecMiniPort
\Device\Beep
\Device\Null
mresgui.dll
TSMSISrv.dll
```

Useful Volatility-style investigation areas include:

- loaded modules,
- unloaded modules,
- kernel drivers,
- suspicious memory regions,
- process module lists,
- network structures.

A key point is that `amonitor.sys` may appear in **unloaded-driver** evidence even after the malware has cleaned up the file from disk.

---

## Original YARA example

The following compact rule is intended as a **research / triage example** for rootkit-like artifacts based on the public RevivalStone findings:

```yara
rule KitsuneHook_Winnti_Rootkit_Artifacts
{
    meta:
        description = "Research detection for Winnti rootkit artifacts described in RevivalStone"
        author = "20dani09"
        source = "LAC RevivalStone public report"

    strings:
        $ipsec = "IPSecMiniPort" wide
        $beep  = "\\Device\\Beep" wide
        $null  = "\\Device\\Null" wide
        $ndis  = "NDIS.SYS" ascii nocase

    condition:
        3 of them
}
```

This should be treated as a **pivot rule**, not a standalone attribution rule.

---

## Original Sigma-style example: suspicious SessionEnv DLL load

```yaml
title: Suspicious SessionEnv Related DLL Load
status: experimental
description: Detects module loading associated with the RevivalStone Winnti execution chain
logsource:
  category: image_load
  product: windows
detection:
  selection_process:
    Image|endswith: '\svchost.exe'
  selection_module:
    ImageLoaded|endswith:
      - '\TSMSISrv.dll'
      - '\mresgui.dll'
  condition: selection_process and selection_module
falsepositives:
  - Unknown
level: high
```

The strongest result would be a match close in time to a `SessionEnv` start.

---

## Original Sigma-style example: rootkit installer creation

```yaml
title: Winnti Rootkit Installer Artifact
status: experimental
description: Detects creation of the RevivalStone rootkit installer filename
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith: '\System32\drivers\amonitor.sys'
  condition: selection
falsepositives:
  - Unknown
level: high
```

---

## Hunting logic: correlated sequence

A higher-confidence analytic could combine several low-frequency events:

```text
SessionEnv transition
    ↓ within minutes
svchost.exe → TSMSISrv.dll
    ↓
mresgui.dll load
    ↓
C:\Windows\Installer\*.dat read
    ↓
amonitor.sys creation
    ↓
AmdK8 configuration change
    ↓
IPSECMINIPORT registry activity
```

A full sequence like this would be far more meaningful than detecting one filename alone.

---

## Network detection considerations

The kernel component is specifically designed to reduce visibility of command-and-control traffic.

Because the RevivalStone rootkit can intercept TCP/IP traffic and the RAT can operate in a passive/listening mode, defenders should not assume an infection will produce a conventional periodic beacon.

Network monitoring should therefore include:

- unsolicited inbound traffic to endpoints that should not expose services,
- unusual traffic that does not align with user-mode socket telemetry,
- discrepancies between host and network sensor views,
- unexplained connections following suspicious kernel-driver activity.

---

## Microsoft Graph abuse

For malware families such as **CUNNINGPIGEON**, destination-based blocking becomes less useful because the communication path abuses legitimate Microsoft infrastructure.

Potential pivots include:

- unusual Graph API access from processes that do not normally use it,
- Graph traffic shortly after code injection,
- mailbox access patterns inconsistent with the logged-on user,
- endpoint processes making Graph requests without an expected Microsoft application context,
- proxy-like network activity following Graph command retrieval.

This should be tuned carefully because Microsoft Graph is widely used by legitimate enterprise applications.

---

## ATT&CK-oriented mapping

The following mapping is based on behavior described in public reporting rather than on the Sherlock question wording.

| Technique | ID | RevivalStone relevance |
|---|---|---|
| Exploit Public-Facing Application | T1190 | ERP SQL injection |
| Server Software Component: Web Shell | T1505.003 | China Chopper, Behinder, sqlmap uploader |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | SessionEnv / TSMSISrv.dll chain |
| Create or Modify System Process: Windows Service | T1543.003 | SessionEnv and AmdK8 abuse |
| Rootkit | T1014 | WINNKIT / Winnti Rootkit |
| Obfuscated/Compressed Files and Information | T1027 | encrypted strings, layered DAT payloads |
| Network Service Discovery / reconnaissance | varies | post-compromise discovery behavior |
| Valid Accounts | T1078 | credential use and lateral movement reported in the campaign |

---

## Defensive takeaway

The most durable detections are based on **rare combinations of behaviors**, not static names.

A practical SOC priority order would be:

```text
1. amonitor.sys creation
2. AmdK8 path modification
3. IPSecMiniPort creation
4. TSMSISrv.dll loaded by svchost.exe
5. suspicious SessionEnv transitions
6. dmdwv.dat or similar payload containers
7. unusual device-object / kernel artifacts
```

Static indicators should be used as pivots into process, service, registry, and memory telemetry rather than as the sole basis for attribution.

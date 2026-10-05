# KitsuneHook — References

## Primary technical sources

### LAC — RevivalStone

**LAC Cyber Emergency Center — “RevivalStone: Attack Campaign Targeting Japanese Organizations by Winnti Group”**  
Published: February 13, 2025

https://www.lac.co.jp/lacwatch/report/20250213_004283.html

Primary source for:

- RevivalStone victimology,
- ERP SQL injection,
- China Chopper / Behinder / sqlmap uploader,
- SessionEnv / TSMSISrv.dll execution chain,
- `mresgui.dll` / PRIVATELOG,
- `dmdwv.dat`,
- AES-OFB and ChaCha20,
- host-specific key derivation,
- `amonitor.sys`,
- AmdK8 abuse,
- `IPSecMiniPort`,
- `\Device\Beep` and `\Device\Null`,
- rootkit IOCTLs,
- detection and memory-forensics guidance,
- Treadstone / StoneV5 PDB-path discussion,
- Winnti v5.0 assessment.

---

### Cybereason — Operation CuckooBees

**Cybereason Nocturnus — “Operation CuckooBees: Deep-Dive into Stealthy Winnti Techniques”**

https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques

**Cybereason Nocturnus — “Operation CuckooBees: A Winnti Malware Arsenal Deep-Dive”**

https://www.cybereason.com/blog/operation-cuckoobees-a-winnti-malware-arsenal-deep-dive

Primary source for:

- 2021 Winnti intrusion activity,
- technology and manufacturing targeting,
- STASHLOG,
- SPARKLOG,
- PRIVATELOG,
- DEPLOYLOG,
- WINNKIT,
- CLFS abuse,
- `prntvpt.dll`,
- PrintNotify service side-loading,
- historical rootkit deployment behavior.

---

## Attribution and naming

### MITRE ATT&CK — Groups

https://attack.mitre.org/groups/

Relevant entries:

- **G0044 — Winnti Group**
- **G0096 — APT41**

MITRE is especially useful here because it explicitly warns that associated group names represent analytical overlap and should not automatically be interpreted as exact equivalence.

### Symantec / Broadcom — APT41, Blackfly and Grayfly

https://www.security.com/threat-intelligence/apt41-indictments-china-espionage

Useful for understanding how Symantec splits activity associated by other vendors with the broader APT41 ecosystem into **Blackfly** and **Grayfly** clusters.

---

## i-SOON / TreadStone

### Recorded Future — Attributing i-SOON

**Insikt Group — “Attributing i-SOON: Private Contractor Linked to Chinese State-Sponsored Cyber Operations”**

https://go.recordedfuture.com/hubfs/reports/cta-2024-0320.pdf

Relevant finding:

- leaked i-SOON material referenced a Linux malware controller using the internal name **TreadStone**,
- Recorded Future connected the naming and tooling to the wider Winnti ecosystem.

---

## CUNNINGPIGEON and related tooling

### JSAC 2025 / JPCERT

Conference material discussing malware used in Winnti-linked activity, including **CUNNINGPIGEON**, **WINDJAMMER**, and **SHADOWGAZE**:

https://jsac.jpcert.or.jp/archive/2025/pdf/JSAC2025_1_2_theo-chen_leon-chang_en.pdf

JPCERT conference summary:

https://blogs.jpcert.or.jp/en/2025/03/jsac2025day1.html

Relevant to:

- Microsoft Graph API abuse,
- mailbox-mediated command retrieval,
- process injection,
- covert network tooling.

---

## Secondary campaign summary

### The Hacker News — RevivalStone coverage

https://thehackernews.com/2025/02/winnti-apt41-targets-japanese-firms-in.html

Useful as a concise English-language summary of LAC's Japanese-language technical report.

---

## Research note

Vendor naming, attribution confidence, and cluster boundaries change as new evidence becomes available.

For that reason, this write-up keeps **campaign facts**, **malware observations**, and **actor naming** conceptually separate rather than collapsing every Winnti-related label into a single identity.

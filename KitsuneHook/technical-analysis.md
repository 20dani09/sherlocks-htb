# KitsuneHook — Technical Analysis

## 1. Analytical context

KitsuneHook is primarily a **threat-intelligence correlation exercise**.

The investigation does not depend on recovering a single malicious binary. Instead, it requires connecting observations across multiple public reports and understanding how vendors describe overlapping portions of the Winnti / APT41 ecosystem.

A useful analytical model is:

```text
Actor / cluster
    ↓
Campaign
    ↓
Initial-access method
    ↓
Post-exploitation tooling
    ↓
Malware deployment chain
    ↓
Kernel stealth / C2
    ↓
Historical and infrastructure links
```

---

## 2. Actor attribution and naming

MITRE ATT&CK tracks **Winnti Group** as `G0044` and **APT41** as `G0096`.

MITRE also states that APT41 overlaps at least partially with reporting on Winnti Group, while its Winnti Group page lists **Blackfly** as an associated designation.

This is a reminder that threat-group names are analytical constructs rather than universal identifiers.

For this investigation, the safest wording is:

> RevivalStone is attributed in public reporting to the Winnti ecosystem, which overlaps with portions of activity tracked by other vendors as APT41, Blackfly, BARIUM, and related clusters.

---

## 3. RevivalStone victimology

LAC observed RevivalStone in March 2024 against Japanese organizations.

The primary sectors were:

- manufacturing,
- materials,
- energy.

This victimology is consistent with a long-running interest in industrial organizations and technology-rich environments where intellectual property, production knowledge, engineering data, and strategic information may be valuable intelligence targets.

---

## 4. Initial compromise

The intrusion chain documented by LAC began with exploitation of an **SQL injection vulnerability** in an unspecified Internet-facing ERP system.

After gaining application-level access, the attacker deployed multiple web shells.

### China Chopper

China Chopper is a compact web shell commonly seen in Chinese-language intrusion ecosystems.

Within RevivalStone it provided an interactive mechanism for operating on the compromised web server and supported progression toward Winnti malware deployment.

### Behinder

Behinder is a multi-platform encrypted web-shell framework.

It is also known publicly as:

```text
Behinder
IceScorpion
Bingxia
```

It supports PHP, ASP, JSP and other server-side environments, and offers capabilities such as command execution, file operations, and proxying.

One implementation detail often associated with default Behinder deployments is the use of key material derived from the MD5 value of the string:

```text
rebeyond
```

This should not be treated as a universal detection condition because operators can modify defaults.

### sqlmap file uploader

LAC also observed a file-upload web shell associated with **sqlmap**.

That finding ties the exploitation workflow directly to SQL-injection tooling and provides an additional clue that exploitation and payload delivery formed one operational chain rather than separate incidents.

---

## 5. Persistence through SessionEnv

The RevivalStone Winnti chain begins with the Windows **Remote Desktop Configuration** service:

```text
Service: SessionEnv
```

The relevant loading sequence is:

```text
SessionEnv
  ↓
SessEnv.dll            legitimate
  ↓
TSMSISrv.dll           attacker-controlled DLL
  ↓
mresgui.dll            Winnti Loader / PRIVATELOG
```

The attacker abuses DLL loading behavior so execution occurs from a trusted Windows service context.

This technique is especially valuable because it combines:

- execution,
- persistence,
- privilege context,
- and masquerading inside normal Windows service behavior.

---

## 6. Winnti loader

LAC identifies `mresgui.dll` as the Winnti Loader and relates it to **PRIVATELOG**.

The loader contains multiple anti-analysis and evasion features, including:

- control-flow flattening,
- indirect jumps,
- encrypted / obfuscated strings,
- XOR,
- ChaCha20,
- copying legitimate libraries before dynamically loading them,
- temporary randomly named DLL copies.

A notable filename pattern observed by LAC was an underscore followed by approximately five to nine alphabetic characters.

Examples documented by the report include names shaped like:

```text
_<letters>.dll
```

The loader deletes temporary copies after use, reducing the persistence of obvious filesystem artifacts.

---

## 7. Encrypted DAT container

The loader reads:

```text
C:\Windows\Installer\dmdwv.dat
```

The DAT file acts as an encrypted container for the next stages of the malware chain.

LAC documented payload entries corresponding to:

- Winnti RAT,
- Winnti Rootkit Installer,
- deployment shellcode,
- Winnti Rootkit.

### Cryptographic flow

The DAT structure is protected with layered encryption.

Victim-specific information contributes to key derivation:

```text
IP address
MAC address
network-interface GUID
```

The high-level process is:

```text
Host-specific values
      ↓
Key derivation
      ↓
AES in OFB mode
      ↓
ChaCha20
      ↓
Decrypted embedded payloads
```

This design creates an analytical obstacle: obtaining the encrypted DAT file may not be sufficient to decrypt the payloads if the original endpoint-specific values are unavailable.

---

## 8. Winnti RAT

After the loader decrypts the required payload, execution transitions to the Winnti RAT.

The RAT continues the deployment chain and is responsible for initiating rootkit installation.

LAC also describes extensive string protection in the RAT, including:

- XOR,
- RC4,
- ChaCha20,
- control-flow flattening.

In the RevivalStone implementation, the RAT behaves as part of a **listening / passive communication architecture** rather than simply performing a conventional periodic callback to a C2 server.

---

## 9. Rootkit installer

The RAT extracts the rootkit installer and writes it as:

```text
%SystemRoot%\System32\drivers\amonitor.sys
```

The legitimate Windows driver service abused in the process is:

```text
AmdK8
```

The general flow is:

```text
Winnti RAT
   ↓
drop amonitor.sys
   ↓
temporarily modify AmdK8 ImagePath
   ↓
start service
   ↓
execute rootkit deployment shellcode
   ↓
restore original AmdK8 configuration
```

Restoring the service configuration after deployment reduces the number of long-lived configuration anomalies visible during later incident response.

---

## 10. WINNKIT / Winnti Rootkit

The final kernel component is commonly referred to as **WINNKIT**.

Its purpose is strongly tied to communication concealment and kernel-level mediation.

### NDIS manipulation

The RevivalStone rootkit registers a dummy NDIS protocol:

```text
IPSecMiniPort
```

It locates TCP/IP-related NDIS structures and modifies protocol handlers, allowing it to inspect or redirect network traffic.

Two handlers highlighted by LAC are associated with send-completion and receive paths.

### Device-object hooks

The rootkit communicates with the user-mode component by hooking `IRP_MJ_DEVICE_CONTROL` on existing Windows device objects.

Important strings include:

```text
\Device\Beep
\Device\Null
```

The RevivalStone-era implementation checks the Beep device before the Null device.

This is useful both as a reverse-engineering clue and as a static detection primitive.

### IOCTL interface

LAC documented control codes including:

```text
0x15E030
0x156008
```

The rootkit supports commands for tasks such as:

- returning its version,
- receiving data,
- sending data,
- stopping operation,
- retrieving BaseNamedObjects-related values.

---

## 11. Passive network architecture

The rootkit hooks networking functionality and waits for specific inbound traffic.

Conceptually:

```text
External operator / C2
        ↓
special inbound traffic
        ↓
Winnti Rootkit
        ↓
Winnti RAT
        ↓
command execution / response
        ↓
Winnti Rootkit
        ↓
network response
```

This passive design can reduce traditional beacon-style indicators because the infected endpoint does not necessarily need to generate a regular outbound callback.

---

## 12. Connection to Operation CuckooBees

Cybereason's **Operation CuckooBees** research documented a Winnti campaign investigated during 2021.

Its malware chain included:

```text
STASHLOG
   ↓
SPARKLOG
   ↓
PRIVATELOG
   ↓
DEPLOYLOG
   ↓
WINNKIT
```

Relevant continuity includes:

- PRIVATELOG,
- WINNKIT,
- abuse of Windows services,
- DLL side-loading,
- kernel-level stealth,
- use of CLFS in the older chain,
- similar operational goals against technology and manufacturing organizations.

Cybereason also documented `prntvpt.dll` as a PRIVATELOG filename used with the **PrintNotify** service.

The compilation timestamps discussed in the KitsuneHook investigation — May 12 and August 17, 2021 — fall within the time period of the intrusions Cybereason investigated.

---

## 13. TreadStone

The **i-SOON leak** provided an unusual view into contractor tooling linked to Chinese cyber operations.

Recorded Future identified a Linux malware controller carrying the internal name:

```text
TreadStone
```

and assessed that it aligned with Winnti-related material referenced in U.S. indictments.

LAC later found the strings:

```text
Treadstone
StoneV5
```

inside PDB path material associated with RevivalStone malware.

The combination is analytically interesting because it provides a naming bridge between:

- leaked contractor material,
- historical Winnti controller terminology,
- and the modernized RevivalStone malware family.

---

## 14. CUNNINGPIGEON

Reporting presented at JSAC 2025 describes **CUNNINGPIGEON**, a backdoor associated with the wider Winnti-linked activity set.

A key feature is its use of **Microsoft Graph API** as part of command-and-control.

Rather than relying only on conventional attacker infrastructure, commands can be obtained from mailbox content through trusted Microsoft services.

Relevant capabilities include:

- command retrieval,
- file management,
- process-related operations,
- custom proxy functionality.

From a SOC perspective, this shifts detection emphasis toward **behavioral context and API usage patterns**, because destination reputation alone may provide little value when the traffic terminates at legitimate Microsoft infrastructure.

---

## 15. Analytical conclusion

RevivalStone demonstrates the durability of the Winnti malware ecosystem.

The most important technical theme is not any single filename or hash. It is the repeated use of layered execution and stealth:

```text
public-facing exploitation
        ↓
web-shell foothold
        ↓
credential access / lateral movement
        ↓
trusted-service execution
        ↓
DLL hijacking
        ↓
encrypted multi-stage payload container
        ↓
user-mode RAT
        ↓
temporary kernel installer
        ↓
network-hooking rootkit
        ↓
passive C2
```

The historical overlap with Operation CuckooBees shows evolution rather than reinvention: components and concepts are reused, modified, and hardened over time.

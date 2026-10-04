# Baggage

## Overview

**Baggage** is a Windows registry forensics Sherlock focused on reconstructing attacker activity from a small KAPE acquisition containing user registry hives.

The investigation centers on the compromised account **`steve`** and reconstructs how the attacker introduced a file-search utility, browsed sensitive local data, accessed a production network share, staged collected files, and compressed the staging directory in preparation for exfiltration.

The most valuable artifacts were:

- `NTUSER.DAT`
- `UsrClass.dat`
- Registry transaction logs
- KAPE acquisition logs

The case is driven primarily by **ShellBags**, with **UserAssist**, **RecentDocs**, and **TypedPaths** used for corroboration.

---

## Evidence set

KAPE was executed against `C:` with the `RegistryHivesUser` target on host:

```text
PROD-WORKSTATIO
```

The acquisition successfully copied all targeted files.

Key evidence for the compromised account:

| Artifact | SHA-1 |
|---|---|
| `C:\Users\steve\NTUSER.DAT` | `36EE1C0F2D3329D98D9E25772A37F73A4C9F72D3` |
| `C:\Users\steve\AppData\Local\Microsoft\Windows\UsrClass.dat` | `E5A8ABF6FC56A2CB40E0C9E6871A01515DC47B14` |

The `NTUSER.DAT` hive was found in a dirty state, so its transaction logs should be replayed before performing a clean registry analysis. `UsrClass.dat` was consistent and could be parsed directly.

---

## High-level attack sequence

The reconstructed activity is:

1. The attacker used the compromised `steve` account.
2. `1.zip` appeared in the user's Downloads directory.
3. The archive contained **Everything 1.4.1.1028**, a fast Windows file-search utility.
4. `everything.exe` was executed from the temporary extraction path.
5. The attacker browsed sensitive directories including:
   - `Engineers Tab`
   - `OnePassword MasterPass`
   - `OT Station 3 internal VPN`
6. The attacker manually entered the UNC path:
   - `\\Prod-ns-2\prodshare`
7. The attacker accessed the `Construction 2027` directory and identified:
   - `Dam Construction Engineer Plans.zip`
8. A staging directory was created at:
   - `C:\Users\steve\Pictures\a`
9. The staging directory was compressed into:
   - `C:\Users\steve\Pictures\a.zip`
10. Explorer recorded access to the final archive at **2025-09-03 07:34:30 UTC**.

The available registry evidence demonstrates **collection and staging for exfiltration**, but does not by itself prove that `a.zip` was successfully transferred off the host.

---

## Key findings

| Finding | Evidence |
|---|---|
| Initial archive | `1.zip` |
| Search utility | Everything 1.4.1.1028 |
| Utility execution | `everything.exe` at 2025-09-03 07:26:57 UTC |
| Password directory | `OnePassword MasterPass` |
| VPN directory | `OT Station 3 internal VPN` |
| VPN folder access | 2025-09-03 07:31:05 UTC |
| Network share | `\\Prod-ns-2\prodshare` |
| Project directory | `Construction 2027` |
| Network archive | `Dam Construction Engineer Plans.zip` |
| Network-share access | 2025-09-03 07:34:04 UTC |
| Staging folder | `C:\Users\steve\Pictures\a` |
| Exfiltration archive | `C:\Users\steve\Pictures\a.zip` |
| Final archive MRU access | 2025-09-03 07:34:30 UTC |

---

## Why ShellBags mattered

The most important evidence came from `UsrClass.dat`.

ShellBags preserved Explorer navigation activity even though the investigation did not include a full disk image. They revealed:

- Sensitive local directories browsed by the attacker.
- The production network share.
- The `Construction 2027` directory.
- The staging directory under `Pictures`.
- The final `a.zip` archive and its navigation timestamp.

This was then corroborated using artifacts from `NTUSER.DAT`.

---

## Repository contents

- [Registry analysis](./registry-analysis.md)
- [Timeline](./timeline.md)
- [Findings and challenge answers](./findings.md)

---

## Scope note

This write-up documents analysis of the provided Hack The Box Sherlock artifacts. No conclusion is made beyond what the available registry evidence can support.

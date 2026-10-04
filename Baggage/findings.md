# Findings and Challenge Answers

## Final answers

| Question | Answer | Primary evidence |
|---|---|---|
| Archive downloaded by the compromised account | `1.zip` | ShellBags / RecentDocs |
| Utility used to search for sensitive data | **Everything 1.4.1.1028** | UserAssist / ShellBags |
| VPN folder access time | **2025-09-03 07:31:05 UTC** | ShellBags MRU |
| Directory containing passwords | `OnePassword MasterPass` | ShellBags |
| Network share UNC path | `\\Prod-ns-2\prodshare` | TypedPaths / ShellBags |
| Planned dam construction year | **2027** | `Construction 2027` |
| Archive on the network share | `Dam Construction Engineer Plans.zip` | ShellBags / registry strings |
| Network-share archive access time | **2025-09-03 07:34:04 UTC** | ShellBags MRU for `Construction 2027` |
| Full staging folder path | `C:\Users\steve\Pictures\a` | ShellBags |
| Exfiltration archive access time | **2025-09-03 07:34:30 UTC** | ShellBags MRU for `a.zip` |

---

## Evidence interpretation

### Downloaded archive

`1.zip` was present under the compromised user's Downloads folder and was also recorded in RecentDocs.

### Search utility

The archive led to:

```text
Everything-1.4.1.1028.x64.zip
```

UserAssist then recorded execution of:

```text
C:\Users\steve\AppData\Local\Temp\Temp1_Everything-1.4.1.1028.x64.zip\everything.exe
```

at **07:26:57 UTC**.

### Sensitive local data

ShellBags identified three particularly sensitive directories:

```text
Engineers Tab
OnePassword MasterPass
OT Station 3 internal VPN
```

The VPN directory's relevant MRU timestamp was **07:31:05 UTC**.

### Production share

TypedPaths contained the UNC path:

```text
\\Prod-ns-2\prodshare
```

This provides direct evidence that the path was entered by the user in Explorer.

The share contained the project directory:

```text
Construction 2027
```

and the archive:

```text
Dam Construction Engineer Plans.zip
```

### Collection and staging

ShellBags showed the attacker creating and navigating:

```text
C:\Users\steve\Pictures\a
```

The directory was then compressed into:

```text
C:\Users\steve\Pictures\a.zip
```

The final archive has multiple timestamps. The challenge's relevant access value is the **ShellBag MRU timestamp**:

```text
2025-09-03 07:34:30 UTC
```

rather than the parsed filesystem-style Accessed value of `07:34:26`.

---

## Confidence

The core findings are strongly supported by multiple registry artifacts.

The one limitation is the final exfiltration step: the evidence clearly shows staging and archive preparation, but the provided dataset does not contain enough network/browser/removable-media telemetry to prove that the archive left the workstation.

# Timeline

All timestamps below are in **UTC**.

| Time | Activity | Artifact |
|---|---|---|
| 2025-09-03 07:09:44 | `Engineers Tab` appears in the user's Documents navigation history | ShellBags |
| 2025-09-03 07:10:58 | `OT Station 3 internal VPN` appears in Documents | ShellBags |
| 2025-09-03 07:12:18 | `OnePassword MasterPass` appears in Documents | ShellBags |
| 2025-09-03 07:24:21 | Microsoft Teams execution recorded | UserAssist |
| 2025-09-03 07:25:08 | Microsoft Edge execution recorded | UserAssist |
| 2025-09-03 07:25:48 | `Downloads\1.zip` created | ShellBags |
| 2025-09-03 07:26:24 | Temporary navigation inside `1.zip`; `Everything-1.4.1.1028.x64.zip` appears | ShellBags |
| 2025-09-03 07:26:57 | `everything.exe` executed | UserAssist |
| 2025-09-03 07:31:05 | `OT Station 3 internal VPN` accessed again | ShellBags MRU |
| 2025-09-03 07:32:23 | `\\Prod-ns-2\prodshare` browsed | ShellBags |
| 2025-09-03 07:33:16 | `C:\Users\steve\Pictures\a` created | ShellBags |
| 2025-09-03 07:34:04 | `Construction 2027` accessed on the production share | ShellBags MRU |
| 2025-09-03 07:34:24 | `C:\Users\steve\Pictures\a.zip` created | ShellBags |
| 2025-09-03 07:34:26 | `a.zip` filesystem metadata records modification/access | ShellBags parsed metadata |
| 2025-09-03 07:34:30 | Explorer records MRU access to `a.zip` | ShellBags MRU |
| 2025-09-03 07:34:40 | Temporary navigation of `a.zip` shows collected content including `Dam Construction Engineer Plans.zip` | ShellBags |

---

## Reconstructed sequence

```text
1.zip
  |
  +--> Everything-1.4.1.1028.x64.zip
          |
          +--> everything.exe executed
                  |
                  +--> sensitive local directories identified
                  |
                  +--> \\Prod-ns-2\prodshare
                         |
                         +--> Construction 2027
                                |
                                +--> Dam Construction Engineer Plans.zip

Collected data
  |
  +--> C:\Users\steve\Pictures\a
          |
          +--> a.zip
                  |
                  +--> MRU access: 2025-09-03 07:34:30 UTC
```

---

## Interpretation

The timeline supports a coherent collection workflow:

- A search utility was introduced and executed.
- Sensitive local data was browsed.
- A production network share was manually accessed.
- Project data was identified.
- The attacker staged material under `Pictures\a`.
- The staging directory was compressed as `a.zip`.

The evidence supports **preparation for exfiltration**, but the supplied registry artifacts do not demonstrate a completed outbound transfer.

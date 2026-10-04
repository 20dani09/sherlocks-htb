# Registry Analysis

## 1. Validate the acquired hives

Before parsing the registry hives, verify that the files match the KAPE acquisition log.

```bash
sha1sum C/Users/steve/NTUSER.DAT
sha1sum C/Users/steve/AppData/Local/Microsoft/Windows/UsrClass.dat
```

Expected SHA-1 values:

```text
36EE1C0F2D3329D98D9E25772A37F73A4C9F72D3  NTUSER.DAT
E5A8ABF6FC56A2CB40E0C9E6871A01515DC47B14  UsrClass.dat
```

---

## 2. Replay NTUSER.DAT transaction logs

The supplied `NTUSER.DAT` was in a dirty state. A clean workflow should replay the associated transaction logs before analysis.

One option is Regipy:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "regipy[full]"
```

Then:

```bash
regipy-process-transaction-logs \
  C/Users/steve/NTUSER.DAT \
  -p C/Users/steve/ntuser.dat.LOG1 \
  -s C/Users/steve/ntuser.dat.LOG2 \
  -o recovered_NTUSER.dat
```

Use the recovered hive for the `NTUSER.DAT` checks below.

---

## 3. ShellBags

The primary artifact for this Sherlock is `UsrClass.dat`.

```bash
regripper \
  -r C/Users/steve/AppData/Local/Microsoft/Windows/UsrClass.dat \
  -p shellbags | tee steve_shellbags.txt
```

Useful filtering:

```bash
grep -Ei '1\.zip|Everything|VPN|OnePassword|Engineers|Prod-ns|Construction|Dam|a\.zip' steve_shellbags.txt
```

Important entries include:

```text
My Computer\CLSID_Downloads\1.zip
Documents\OnePassword MasterPass
Documents\Engineers Tab
Documents\OT Station 3 internal VPN
My Network Places\Prod-ns-2\\Prod-ns-2\prodshare
My Network Places\Prod-ns-2\\Prod-ns-2\prodshare\Construction 2027
Pictures\a
Pictures\a.zip
```

The ShellBag for the final archive records:

```text
MRU Time:  2025-09-03 07:34:30
Modified:  2025-09-03 07:34:26
Accessed:  2025-09-03 07:34:26
Created:   2025-09-03 07:34:24
Resource:  ...\Pictures\a.zip
```

For the Sherlock question asking when the archive was accessed, the relevant value is the **ShellBag MRU Time: 2025-09-03 07:34:30 UTC**.

This distinction matters: the filesystem-style Accessed timestamp and the ShellBag MRU timestamp are not the same thing.

---

## 4. UserAssist

Use UserAssist to prove that the attacker actually executed the search utility.

```bash
regripper -r recovered_NTUSER.dat -p userassist
```

Key entry:

```text
2025-09-03 07:26:57Z
C:\Users\steve\AppData\Local\Temp\Temp1_Everything-1.4.1.1028.x64.zip\everything.exe
```

This confirms execution of **Everything 1.4.1.1028**, rather than merely the presence of the archive on disk.

---

## 5. RecentDocs

```bash
regripper -r recovered_NTUSER.dat -p recentdocs
```

Relevant entries:

```text
a.zip
a
Dam Construction Engineer Plans.zip
1.zip
```

This corroborates direct user interaction with both the downloaded archive and the staged archive.

---

## 6. TypedPaths

```bash
regripper -r recovered_NTUSER.dat -p typedpaths
```

Relevant result:

```text
url1     \\Prod-ns-2\prodshare
url2     Documents
```

This is particularly useful because it shows that the attacker explicitly entered the production UNC path in Explorer.

---

## 7. MountPoints2

```bash
regripper -r recovered_NTUSER.dat -p mp2
```

The artifact contained volume identifiers but did not provide sufficient evidence to establish a USB-based exfiltration path.

Because the acquisition did not include the `SYSTEM` hive, the volume GUIDs could not be reliably correlated with `MountedDevices` or USBSTOR data.

Therefore, no USB exfiltration conclusion was made.

---

## 8. ZIP file association

The user's `.zip` association can be queried directly with `Parse::Win32Registry`:

```bash
perl -MParse::Win32Registry -E '
$r=Parse::Win32Registry->new("recovered_NTUSER.dat");
$k=$r->get_root_key->get_subkey(
  "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.zip\\UserChoice"
);
for $v ($k->get_list_of_values){
  say $v->get_name." = ".$v->get_data
}'
```

Result:

```text
ProgId = CompressedFolder
```

The native Windows compressed-folder handler was associated with ZIP files. No evidence from the analyzed registry artifacts established use of WinRAR or 7-Zip.

---

## 9. Additional checks

The following artifacts were checked but did not provide meaningful attacker activity:

- `RunMRU`: no values.
- `WordWheelQuery`: not present.
- `ComDlg32`: not present.
- `AttachmentExecute`: not present.
- RDP client history: no entries.
- Internet Explorer `TypedURLs`: only a default Microsoft URL.

These negative findings helped narrow the investigation toward Explorer, ShellBags, and Everything.

---

## 10. Raw string triage

Registry string searches can be useful for quickly locating additional references:

```bash
strings -el \
  C/Users/steve/NTUSER.DAT \
  C/Users/steve/AppData/Local/Microsoft/Windows/UsrClass.dat \
  | grep -Ei 'prodshare|construction|password|vpn|engineer|everything|\.zip'
```

This exposed references including:

```text
1.zip
Everything-1.4.1.1028.x64.zip
Construction 2027
Dam Construction Engineer Plans.zip
\\Prod-ns-2\prodshare
Engineers Tab
OnePassword MasterPass
OT Station 3 internal VPN
a.zip
```

String searching was used as supporting triage only; structured registry artifacts were preferred for conclusions.

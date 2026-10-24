# Kraken — Findings and HTB Challenge Answers

The following twelve answers correspond to the solved Sherlock questions. Dates are UTC. The **evidence column** identifies what supports each answer, rather than presenting unverified deductions as measurements.

| # | Question | Answer | Evidence / method |
|---|---|---|---|
| 1 | Exact execution date/time of malicious file | **2025-06-13 14:43:27** | <code>WSCRIPT.EXE-3FF4D889.pf</code> last run at 14:43:27.197376 UTC; <code>Conf.js.lnk</code> corroboration |
| 2 | First dropped file | **temp_993805.bat** | <code>Conf.js</code> uses the Windows Temp special folder plus randomized <code>temp_*.bat</code>; AD1 contains matching file |
| 3 | Six bytes used to force return value zero | **0xB8,0x0,0x00,0x00,0x00,0xC3** | Decoded PowerShell variable <code>$optimizationData</code> |
| 4 | File responsible for second-stage PE loading | **dwm.bat** | Batch self-copy command, then PowerShell parses/decrypts blobs in this file |
| 5 | SHA-1 of the auxiliary PE (not malicious by itself) | **339e27243df24f2b8979e78711e396698f4f47cc** | SHA-1 of recovered first 4,096-byte .NET assembly |
| 6 | Encrypted resource in third stage | **xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe** | <code>ManifestResource</code> of the 31,232-byte .NET PE |
| 7 | Key and IV for the final resource | **Key:** <code>ALWIGeOnxudniHR2K4CNZmnaEZffXt6zKsRFoAM2/mA=</code>; **IV:** <code>JXYbOTuuz3cErOl30kAKhw==</code> | Stage-2 assembly's embedded strings and AES-CBC decode |
| 8 | SHA-1 after decryption | **052c0687f023564a3c31fb652bea3405341272cb** | SHA-1 of the 49,664-byte, GZip-inflated final PE |
| 9 | Mobile User-Agent in final PE | **See exact string below** | UTF-16LE strings inside recovered PE |
| 10 | Variable holding the mutex | **Territories** | .NET static field <code>Antarctica.Territories</code> of type <code>System.Threading.Mutex</code> |
| 11 | IP:port of C2 connection | **107.172.232.84:2468** | 2025-06-11 Unit 42 exact-hash IOC bulletin + later ANY.RUN Connections (**external**, not local AD1) |
| 12 | Full path to persistence file | **C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\5c74.bat** | File inside AD1 and Startup-folder persistence technique |

## Q9 — Full mobile User-Agent

~~~text
Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1
~~~

The other two User-Agents impersonate Firefox 66.0 on Windows 7 and Chrome 60 on Windows 10.

## Q3 — Six-byte patch interpretation

~~~asm
B8 00 00 00 00     mov eax, 0
C3                 ret
~~~

The deobfuscated PowerShell defines:

~~~powershell
$optimizationData = [byte[]](0xb8,0x0,0x00,0x00,0x00,0xC3)
~~~

These bytes are associated with an AMSI-related scan-function patch. This is **different** from the x64 ETW patch, which writes the single byte <code>C3</code> to <code>EtwEventWrite</code>.

## Q5 and Q8 — Hash verification

The analyst recovered both PEs by decrypting and decompressing embedded data **without executing** the files. Reproduce from the supplied batch via [tools/recover_payloads.py](./tools/recover_payloads.py):

~~~bash
python3 tools/recover_payloads.py /path/to/5c74.bat --out ./recovered
sha1sum recovered/payload_0_unpacked.bin
sha1sum recovered/payload_1_embedded_unpacked.bin
~~~

Expected results:

~~~text
339e27243df24f2b8979e78711e396698f4f47cc  recovered/payload_0_unpacked.bin
052c0687f023564a3c31fb652bea3405341272cb  recovered/payload_1_embedded_unpacked.bin
~~~

The term “not malicious on its own” describes the first auxiliary assembly's role in the exercise; **a single file's benignness cannot be established from a hash or small size alone**.

## Q6–Q8 — Stage boundary

Do not mix the separate crypto layers:

1. The batch-loader's AES-CBC/GZip layer yields the 4,096-byte auxiliary PE and the 31,232-byte stage-2 PE.
2. The **stage-2 assembly** contains a managed resource named <code>xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe</code> and a **different** AES key/IV.
3. Decrypting and inflating that resource yields the final 49,664-byte PE, internally named <code>MasonClient1.exe</code>.

## Q11 — How the IP was established

The local final PE contains <code>apostlejob3.duckdns.org</code> and port <code>2468</code>, **not a proven destination IP**.

A [Unit 42 bulletin published on 2025-06-11](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2025-06-11-IOCs-for-Neptune-RAT-version-5.3.txt) already associated the recovered final PE's full SHA-256 with **107.172.232.84:2468** and the same DDNS hostname. This is stronger temporal corroboration because it predates the 2025-06-13 victim incident.

A [public ANY.RUN report for the exact SHA-256](https://any.run/report/9d86ea12e0643cd79f6f97202716d6e7b2a0f2dc81b9255719bb5ca7aaeebd12/e51a4b2f-a59e-490b-b90f-92abd400e6c5) lists process <code>xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe</code> (PID 6644) connecting to <code>107.172.232.84:2468</code> with domain <code>apostlejob3.duckdns.org</code>. The sandbox report dates to **2026-06-04**, not the victim's 2025-06-13 incident.

For historical-DNS context, another sandbox run of the matching initial JS (2025-05-27) showed that same hostname resolving to **185.167.160.222**; hostname/IP mappings must be time-scoped. The case's accepted IP remains **107.172.232.84**.

## Q12 — Why the Startup path matters

Windows launches contents of a user's <code>Startup</code> folder on interactive logon. The recovered file's SHA-256 matches both <code>temp_993805.bat</code> and <code>dwm.bat</code>:

~~~text
bd2cc2f1f25b5f520a87068475247dd5611ab9f199ed3264983d720e016acf66
~~~

This implements **MITRE ATT&CK T1547.001 (Registry Run Keys / Startup Folder)**. The local evidence proves the file was placed for persistence; it does not prove every future autorun took place.

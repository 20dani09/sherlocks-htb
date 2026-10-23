# Kraken — Forensic Timeline

All times are **UTC** on 2025-06-13. The AD1 timestamps below refer to the logical-image metadata. **Created, modified, and accessed are different events.** The modified time of a copied BAT may retain the timestamp of its source.

## Timeline

| UTC | Event | Evidence / interpretation |
|---|---|---|
| 14:35:07 | Windows network-connectivity activity | NetworkProfile operational log; background connectivity, **not proof of C2** |
| 14:36:48 | Local PDF accessed through Edge | <code>The_Art_Of_War.pdf</code>; contextual, not a malicious-execution timestamp |
| **14:43:27.197376** | **Windows Script Host execution** | <code>WSCRIPT.EXE-3FF4D889.pf</code> last-run FILETIME, references <code>Conf.js</code> |
| 14:43:27.446396 | <code>Conf.js.lnk</code> created | <code>Administrator\AppData\Roaming\Microsoft\Windows\Recent</code> |
| **14:43:28.090140** | **First BAT dropped** | Created/modified timestamp of <code>AppData\Local\Temp\temp_993805.bat</code> |
| **14:43:29.871086** | <code>dwm.bat</code> created | In the user's profile; its modified timestamp remains 14:43:28.090140 |
| ~14:43:36–14:43:40 | PowerShell execution and script activity | PowerShell Operational event records containing the decoded loader/in-memory patching code |
| **14:43:41.099288** | **Startup persistence file created** | <code>Startup\5c74.bat</code>. Its modified timestamp also remains 14:43:28.090140 |
| 14:43:44.589312 | <code>dwm.bat</code> last-access metadata | AD1 logical-image metadata; not necessarily a unique execution event |
| 14:43:49.699470 | <code>5c74.bat</code> last-access metadata | AD1 logical-image metadata |

### Crucial distinctions

- The challenge asks **when the user executed the malicious file**: the best-supported answer is the **Prefetch last-run time**, rounded to <code>2025-06-13 14:43:27</code>, not the first BAT's creation time.
- <code>Conf.js.lnk</code> corroborates that the file was opened; its creation timestamp is slightly later than the Prefetch execution time.
- The Startup BAT's **created** timestamp is <code>14:43:41.099288</code>, whereas its **modified** timestamp is <code>14:43:28.090140</code>. Treating the latter as the creation time would be a forensic error.
- The evidence strongly supports execution of the loader, but local network logs do not establish whether the RAT completed a C2 handshake.

## Reproducing the execution timestamp

1. Export <code>Windows\Prefetch\WSCRIPT.EXE-3FF4D889.pf</code> from the AD1 image.
2. The Prefetch starts with <code>MAM\x04</code>, indicating a compressed Windows Prefetch (XPRESS Huffman).
3. Decode the Prefetch with an XPRESS-Huffman-aware parser and inspect its last execution FILETIME. The decompressed <code>SCCA</code> Prefetch version is 30.
4. For this sample the most recent execution FILETIME corresponds to:

~~~text
2025-06-13 14:43:27.197376+00:00
~~~

5. Search its referenced file strings for <code>CONF.JS</code> and corroborate with <code>Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\Conf.js.lnk</code>.

Avoid simply running <code>strings</code> against the compressed <code>.pf</code>; its string table will not appear as plain UTF-16 until decompressed.

## Reproducing file creation timestamps

Export the named BAT files from the AD1 container using an AD1-aware forensic tool. Review file metadata's **Created** values in UTC:

~~~text
.../Temp/temp_993805.bat       2025-06-13 14:43:28.090140
.../Administrator/dwm.bat      2025-06-13 14:43:29.871086
.../Programs/Startup/5c74.bat 2025-06-13 14:43:41.099288
~~~

These are logical-image metadata values, not Windows Event ID 4688 process-creation events.

## Uncertainties

The supplied image lacks sufficiently detailed host-level packet/network records to establish a live connection to the configured C2. Sandbox traffic from an externally executed copy of the exact final PE is documented separately in [network-analysis.md](./network-analysis.md).

# Stonks — Challenge Findings and Evidence Index

Answers are presented in the format expected by the Hack The Box Sherlock. **Evidence interpretation** is kept separate from puzzle wording.

| # | Question / focus | Answer | Primary supporting artifact |
|---:|---|---|---|
| 1 | First Windows Data Deduplication installation | **`2025-09-18 09:56:40`** UTC | `System.evtx`, SCM Event 7045, record 5237 (service installed); `Setup.evtx` records package completion one second later |
| 2 | Space saved by first successful optimization job (bytes) | **`6805707`** | `Microsoft-Windows-Deduplication/Operational`, record 5, `SavedSpace` with `ErrorCode=0` |
| 3 | Most recent re-enablement / configuration change of D: | **`2025-09-20 03:34:35`** UTC | `dedupConfig.01.xml`, `changeTime=134028128759740533`; this records a configuration change and does *not alone* identify the specific action |
| 4 | File extensions excluded from optimization, alphabetically | **`avi, bak, edb, iso, jrs, mp4, tif`** | `dedupConfig.01.xml`: custom `excludeFileExtensions` plus `excludeFileExtensionsDefault` |
| 5 | Number of optimized files | **`168`** | `State\dedupStatistics.xml`, `optimizedFileCount` |
| 6 | Next Throughput Optimization run | **`2025-09-25 06:50:00`** | `Windows\System32\Tasks\Microsoft\Windows\Deduplication\ThroughputOptimization`: Thursdays at 06:50 server-local |
| 7 | Deleted financial report | **`Internal Consolidated Financial Statements 2024.docx`** | `Finance\Reports\Annual\2024`, AD1 file index and NTFS MFT #46 |
| 8 | MFT record number | **`46`** | `D:\$MFT` |
| 9 | File attribute flags, ascending hex | **`FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_REPARSE_POINT`** | MFT #46, `$STANDARD_INFORMATION`, `FileAttributes=0x0620` |
| 10 | $REPARSE_POINT absolute file offset | **`0x0000B9B0`** | MFT #46 base `0xB800` + attribute relative `0x1B0` |
| 11 | Number of deduplicated chunks | **`2`** | Dedup `Stream/*.ccc`, matching `Smap` at `0x52C8` |
| 12 | Data length of first chunk | **`61095`** | Dedup `Smap` and `Data/*.ccc`, first chunk |
| 13 | Recovered file SHA-256 | **`e51e773e5404f29cc2816cff3fbdcc8b2c28f9e8040a6e7fe926b21336b66513`** | Reconstructed 90,593-byte DOCX; 29 ZIP members, integrity OK |
| 14 | Document's recorded author | **`Elaine Chua`** | Recovered DOCX, `docProps/core.xml`, `dc:creator` |
| 15 | Overstated annual profit (`$'000`) | **`4319751`** | 2024 consolidated profit-and-loss tables: `2,672,196 − (−1,647,555)` |

## Precision notes

1. **First installation:** `System.evtx` event 7045 refers to service installation; `Setup.evtx` reflects component/package completion. These events are not interchangeable.
2. **Re-enabled time:** the XML `changeTime` is strong timestamp evidence for a Dedup configuration change, but proving *reenablement itself* would require corresponding state-transition records or commands. The challenge accepts the timestamp as its answer.
3. **Two savings numbers:** the first successful optimization job reports **6,805,707 bytes**; later `dedupStatistics.xml` lists `savingsSize = 6,618,438`. They represent different measurements.
4. **Two different flags:** MFT record header `Flags=0x0000` means the record is not in use; FILE_ATTRIBUTE bitmask `0x0620` describes Archive/Sparse/Reparse.
5. **Next scheduled job:** `06:50` is the scheduled server-local time; this is *not* proof of execution.
6. **Profit units:** HTB expects **4,319,751** because the source financial values are in `$'000`. Equivalent individual dollars are **4,319,751,000**.
7. **Author vs culpability:** the DOCX creator property identifies the recorded author, **not criminal responsibility**.

For the underlying evidence and reproduction method, read [forensic-analysis.md](./forensic-analysis.md), [recovery-walkthrough.md](./recovery-walkthrough.md), and [financial-comparison.md](./financial-comparison.md).

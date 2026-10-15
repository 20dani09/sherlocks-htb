# Stonks — Forensic Evidence and Timeline

This page documents **what was observed** in the supplied AD1 acquisition and Windows event logs. It separates installation, configuration and optimization, because these are distinct stages of Data Deduplication.

## Evidence inventory

- `evidence.ad1`: logical AccessData AD1 image, mounted in FTK Imager as a multi-volume content image.
- Partition 2: `NONAME`, NTFS (~40,095 MB according to the evidence tree).
- Partition 3: `Data`, NTFS (~512 MB), mapped to D: in the case.
- Supporting Windows EVTX exports, including `System.evtx`, `Setup.evtx` and `Microsoft-Windows-Deduplication%4Operational.evtx`.

Core files examined in D::

```text
D:\
├── $MFT
├── Finance\
│   └── Reports\Annual\2024\
│       ├── Audited Consolidated Financial Statements 2024.docx
│       └── Internal Consolidated Financial Statements 2024.docx [deleted]
└── System Volume Information\
    └── Dedup\
        ├── Settings\dedupConfig.01.xml
        ├── State\dedupStatistics.xml
        └── ChunkStore\{6F89FF76-AE45-4802-BD0E-4075177C075F}.ddp\
            ├── Stream\00010000.00000001.ccc
            └── Data\00000001.00000001.ccc
```

Some AD1 entries, including the deleted report, are *logical references* rather than directly exportable original bytes; the Dedup containers are essential for reconstruction.

## Installation, policy changes and scheduled jobs

| Timestamp | Artifact | Observation / limitation |
|---|---|---|
| 2025-09-18 **09:56:40 UTC** | `System.evtx`, Service Control Manager, **Event 7045**, Record ID 5237 | Installation of the Data Deduplication Service was recorded |
| 2025-09-18 **09:56:41 UTC** | `Setup.evtx`, Microsoft-Windows-Servicing, Record ID 98 | Dedup-Core package installation completed; this is **not** the earliest service installation event |
| 2025-09-18 **10:11:07 UTC** | Deduplication Operational EVTX, Record ID 5 | Optimization job success (`ErrorCode=0`); `SavedSpace=6805707` bytes |
| 2025-09-20 **03:34:35.974053 UTC** | `Settings\dedupConfig.01.xml` | `changeTime=134028128759740533` (Windows FILETIME); **configuration timestamp**, consistent with a change around volume re-enablement, but not by itself proof of the precise operation |
| 2025-09-25 **06:50:00 local server time** | `Windows\System32\Tasks\Microsoft\Windows\Deduplication\ThroughputOptimization` | Next Thursday occurrence after the evidence date, derived from weekly Thursday 06:50 task trigger |

**Time caution:** An XML `StartBoundary` without an explicit timezone should not be silently described as UTC. The config `changeTime` is a UTC FILETIME; the task start boundary is the Windows scheduled task's local-time definition.

### The Throughput Optimization schedule

```xml
<StartBoundary>2025-09-20T06:50:00</StartBoundary>
<ScheduleByWeek>
  <DaysOfWeek><Thursday /></DaysOfWeek>
  <WeeksInterval>1</WeeksInterval>
</ScheduleByWeek>
```

The next Thursday after Saturday, September 20, 2025, is **2025-09-25**, giving `2025-09-25 06:50:00`. This is the *scheduled* time; it does not prove the job actually ran.

## Dedup configuration and metrics

Both `dedupConfig.01.xml` and `dedupConfig.02.xml` have the same relevant exclusions:

```xml
<property name='excludeFileExtensions' type='VT_BSTR' value='mp4|avi|iso|bak|tif' />
<property name='excludeFileExtensionsDefault' type='VT_BSTR' value='edb|jrs' />
```

Sorted combined list: **`avi, bak, edb, iso, jrs, mp4, tif`**.

The separate `noCompressionFileExtensions` property means **no compression** for certain types; it must not be interpreted as a list of files excluded from **optimization**.

Key values observed in `State\dedupStatistics.xml`:

| Field | Value |
|---|---:|
| `optimizedFileCount` | **168** |
| `nonOptimizedFileCount` | **2** |
| `optimizedLogicalFileSize` | 108,666,867 bytes |
| `savingsSize` | 6,618,438 bytes |
| `savingsPercent` | 6 |
| `actualSavingsPercent` | 5 |

**Important:** `savingsSize=6618438` describes recorded volume statistics in this snapshot. It is **not** the same measurement as the first successful optimization job's `SavedSpace=6805707` event. Both values are presented without conflating them.

## NTFS $MFT record #46

The acquired `D:\$MFT` contains 524,288 bytes. This record has 1,024-byte slots, so file record #46 begins at:

```text
46 * 1024 = 47,104 = 0xB800
```

The record starts with the `FILE` signature. Its record header `Flags` field (at relative `0x16`) is **`0x0000`**, so `InUse=0`. This supports **deletion**, not author attribution.

```text
$MFT record #46 (absolute offsets)
0x0000B800  record begins ("FILE")
0x0000B816  record flags: 0x0000 (not in use)
0x0000B838  $STANDARD_INFORMATION (0x10)
0x0000B898  $FILE_NAME (0x30)
0x0000B960  $DATA (0x80)
0x0000B9B0  $REPARSE_POINT (0xC0)
```

The `$STANDARD_INFORMATION` FILE_ATTRIBUTE bitmask is **`0x0620`**:

| Name | Hex |
|---|---|
| `FILE_ATTRIBUTE_ARCHIVE` | `0x0020` |
| `FILE_ATTRIBUTE_SPARSE_FILE` | `0x0200` |
| `FILE_ATTRIBUTE_REPARSE_POINT` | `0x0400` |

These are **not** the same flags as the MFT record header (`0x0000`). The `$REPARSE_POINT` contains the Dedup tag **`0x80000013`**, which is more specific evidence of an optimized file.

## What this evidence does *not* establish

The preserved filename, release of MFT record #46, and two recoverable chunks show that a document was present, deleted from the filesystem, and recoverable from this image. They do **not** independently prove which person performed the deletion, whether it was intentional concealment, or whether anyone is guilty of fraud.

Continue with [byte-by-byte recovery](./recovery-walkthrough.md), or [financial comparison](./financial-comparison.md).

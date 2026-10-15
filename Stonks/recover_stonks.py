#!/usr/bin/env python3
"""Recover the deleted Stonks DOCX directly from the provided AD1 acquisition.

Case-specific, read-only parser; not a general AD1/Windows Dedup decoder.
Usage: python3 recover_stonks.py evidence.ad1 -o recovered_report.docx
"""
import argparse
import hashlib
import io
import mmap
import struct
import zipfile
from pathlib import Path
import zlib

AD1_BASE = 0x200
MFT_ENTRY = 46
RECORD_SIZE = 1024
EXPECTED_SIZE = 90593
EXPECTED_SHA256 = "e51e773e5404f29cc2816cff3fbdcc8b2c28f9e8040a6e7fe926b21336b66513"


def u16(buf, offset):
    return struct.unpack_from("<H", buf, offset)[0]


def u32(buf, offset):
    return struct.unpack_from("<I", buf, offset)[0]


def u64(buf, offset):
    return struct.unpack_from("<Q", buf, offset)[0]


class StonksAD1:
    """Minimal decoder for this exercise's AD1 tree and zlib data blocks."""

    def __init__(self, path):
        self.fh = open(path, "rb")
        self.mm = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ)
        if (self.mm[:15] != b"ADSEGMENTEDFILE" or
                self.mm[AD1_BASE:AD1_BASE + 14] != b"ADLOGICALIMAGE"):
            self.close()
            raise ValueError("Unexpected AD1 signature")
        self.entries = []
        self._scan()

    def close(self):
        self.mm.close()
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _scan(self):
        visited = set()

        def walk(offset, parent, depth=0):
            if depth > 100:
                raise ValueError("AD1 tree too deep")
            while offset:
                if offset in visited:
                    return
                visited.add(offset)
                sibling = u64(self.mm, offset)
                child = u64(self.mm, offset + 8)
                descriptor = u64(self.mm, offset + 24)
                size = u64(self.mm, offset + 32)
                n = u32(self.mm, offset + 44)
                if n > 4096:
                    raise ValueError("Unreasonable AD1 name length")
                name = self.mm[offset + 48:offset + 48 + n].decode("utf-8", "replace")
                full_path = parent + "/" + name
                self.entries.append((full_path, descriptor, size))
                if child:
                    walk(AD1_BASE + child, full_path, depth + 1)
                offset = AD1_BASE + sibling if sibling else 0

        walk(AD1_BASE + u32(self.mm, AD1_BASE + 0x24), "")

    def extract(self, filename, directory):
        matches = [(p, d, s) for p, d, s in self.entries
                   if p.rsplit("/", 1)[-1].lower() == filename.lower()
                   and directory.lower() in p.lower()]
        if len(matches) != 1:
            raise ValueError(f"Expected one {filename!r} in {directory!r}, found {len(matches)}")
        path, descriptor, expected = matches[0]
        if not descriptor:
            raise ValueError(f"No content descriptor for {path}")
        print(f"[+] AD1 entry: {path} ({expected:,} bytes)")
        table = AD1_BASE + descriptor
        count = u64(self.mm, table)
        if count > 100000:
            raise ValueError("Invalid AD1 block count")
        output = bytearray()
        for i in range(count):
            start = AD1_BASE + u64(self.mm, table + 8 + 8 * i)
            dz = zlib.decompressobj()
            output.extend(dz.decompress(self.mm[start:start + 0x12000]))
            if not dz.eof:
                raise ValueError(f"Incomplete zlib block {i}")
        if len(output) != expected:
            raise ValueError("Extracted length differs from AD1 record size")
        return bytes(output)


def find_reparse(mft):
    """Extract the resident Dedup $REPARSE_POINT from deleted NTFS entry #46."""
    rec = mft[MFT_ENTRY * RECORD_SIZE:(MFT_ENTRY + 1) * RECORD_SIZE]
    if rec[:4] != b"FILE":
        raise ValueError("Entry #46 is not an NTFS FILE record")
    flags = u16(rec, 0x16)
    if flags & 1:
        raise ValueError("MFT record #46 is not marked deleted")
    print(f"[+] MFT #46 Flags=0x{flags:04x} (not in use)")
    pos = u16(rec, 0x14)
    while pos + 24 <= len(rec):
        typ = u32(rec, pos)
        if typ == 0xffffffff:
            break
        size = u32(rec, pos + 4)
        if size < 24 or pos + size > len(rec):
            raise ValueError("Invalid NTFS attribute length")
        if typ == 0xC0:
            if rec[pos + 8]:
                raise ValueError("Expected a resident $REPARSE_POINT")
            n = u32(rec, pos + 16)
            data_offset = u16(rec, pos + 20)
            if data_offset + n > size:
                raise ValueError("Resident data exceeds attribute size")
            result = rec[pos + data_offset:pos + data_offset + n]
            if u32(result, 0) != 0x80000013:
                raise ValueError("Not the expected Windows Dedup reparse tag")
            print(f"[+] $REPARSE_POINT at 0x{MFT_ENTRY * RECORD_SIZE + pos:08x}")
            return result
        pos += size
    raise ValueError("No Dedup $REPARSE_POINT found")


def reconstruct(reparse, stream, data):
    if len(reparse) < 128:
        raise ValueError("Truncated reparse data")
    stream_id = reparse[96:128]
    where = stream.find(stream_id)
    if where < 0 or stream.find(stream_id, where + 1) >= 0:
        raise ValueError("Stream ID missing or non-unique")
    header = where - 0x38
    if header < 0 or stream[header:header + 4] != b"Ckhr":
        raise ValueError("Stream Ckhr not found")
    smap_offset = header + 0x68
    smap_size = u32(stream, header + 0x0c)
    smap = stream[smap_offset:smap_offset + smap_size]
    if len(smap) != smap_size or smap[:4] != b"Smap" or (smap_size - 8) % 64:
        raise ValueError("Malformed Smap")
    count = (smap_size - 8) // 64
    print(f"[+] Smap 0x{smap_offset:x}: {count} chunks")
    result = bytearray()
    for i in range(count):
        start = 8 + 64 * i
        chunk_no, container_no, offset, file_no, logical_end, chunk_id, n = struct.unpack_from(
            "<IIIIQ32sQ", smap, start)
        if container_no != 1 or file_no != 1:
            raise ValueError("Unexpected container (this parser is case-specific)")
        if data[offset:offset + 4] != b"Ckhr" or u32(data, offset + 0x0c) != n:
            raise ValueError("Bad or inconsistent chunk header")
        payload_offset = offset + 0x58  # 88-byte header in this image
        payload = data[payload_offset:payload_offset + n]
        if len(payload) != n:
            raise ValueError("Truncated chunk")
        result.extend(payload)
        if len(result) != logical_end:
            raise ValueError("Smap logical end mismatch")
        print(f"[+] Chunk {i + 1}: ID={chunk_no}, header=0x{offset:x}, "
              f"payload=0x{payload_offset:x}, length={n:,}")
    return bytes(result)


def main():
    p = argparse.ArgumentParser(description="Recover the deduplicated Stonks report from evidence.ad1")
    p.add_argument("ad1", type=Path)
    p.add_argument("-o", "--output", type=Path, default=Path("recovered_report.docx"))
    args = p.parse_args()
    with StonksAD1(args.ad1) as image:
        mft = image.extract("$MFT", "Partition 3")
        stream = image.extract("00010000.00000001.ccc", "/Stream/")
        data = image.extract("00000001.00000001.ccc", "/Data/")
    reparse = find_reparse(mft)
    result = reconstruct(reparse, stream, data)
    digest = hashlib.sha256(result).hexdigest()
    print(f"[+] Recovered {len(result):,} bytes, SHA-256 {digest}")
    if len(result) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise ValueError("Reconstruction failed size/SHA-256 verification")
    with zipfile.ZipFile(io.BytesIO(result)) as z:
        bad = z.testzip()
        if bad is not None:
            raise ValueError(f"DOCX ZIP integrity error: {bad}")
        print(f"[+] DOCX ZIP integrity OK ({len(z.namelist())} entries)")
    args.output.write_bytes(result)
    print(f"[+] Wrote {args.output}")


if __name__ == "__main__":
    main()

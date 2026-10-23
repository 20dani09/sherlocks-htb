#!/usr/bin/env python3
"""Offline extraction of the three managed PE stages from a Kraken batch file.

Requires: pip install cryptography
Never executes the BAT or recovered PEs. Use only in an isolated analysis lab.
"""
import argparse
import base64
import gzip
import hashlib
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

LAYER1_KEY = 'ImocNEnUZbHBmaXIBtoy7X3HCr9QsCDJAUlkq43qYFg='
LAYER1_IV = 'WCpQVGqc+E4SNHfKYV5jVQ=='
LAYER2_KEY = 'ALWIGeOnxudniHR2K4CNZmnaEZffXt6zKsRFoAM2/mA='
LAYER2_IV = 'JXYbOTuuz3cErOl30kAKhw=='

EXPECTED_SHA1 = {
    'payload_0_unpacked.bin': '339e27243df24f2b8979e78711e396698f4f47cc',
    'payload_1_unpacked.bin': '0c4236fd5a8b2cd632da0c1e06444e0a95bb7cd3',
    'payload_1_embedded_unpacked.bin': '052c0687f023564a3c31fb652bea3405341272cb',
}


def aes_gzip(ciphertext: bytes, b64key: str, b64iv: str) -> bytes:
    key = base64.b64decode(b64key, validate=True)
    iv = base64.b64decode(b64iv, validate=True)
    if len(ciphertext) % 16:
        raise ValueError('AES-CBC ciphertext is not block-aligned')
    ctx = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = ctx.update(ciphertext) + ctx.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return gzip.decompress(plaintext)


def rva_to_offset(pe: bytes, rva: int) -> int:
    peoff = struct.unpack_from('<I', pe, 0x3c)[0]
    if pe[:2] != b'MZ' or pe[peoff:peoff + 4] != b'PE\0\0':
        raise ValueError('Not a supported PE file')
    count = struct.unpack_from('<H', pe, peoff + 6)[0]
    optsize = struct.unpack_from('<H', pe, peoff + 20)[0]
    section_base = peoff + 24 + optsize
    for i in range(count):
        pos = section_base + i * 40
        virtual_size, virtual_address, raw_size, raw_off = struct.unpack_from('<IIII', pe, pos + 8)
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return raw_off + rva - virtual_address
    raise ValueError(f'RVA not mapped to a PE section: {rva:x}')


def dotnet_resource(pe: bytes) -> bytes:
    peoff = struct.unpack_from('<I', pe, 0x3c)[0]
    opt = peoff + 24
    magic = struct.unpack_from('<H', pe, opt)[0]
    if magic not in (0x10b, 0x20b):
        raise ValueError('Unsupported PE optional header')
    dd = opt + (96 if magic == 0x10b else 112)
    cli_rva, cli_size = struct.unpack_from('<II', pe, dd + 14 * 8)
    if not cli_rva or not cli_size:
        raise ValueError('Missing CLI/.NET data directory')
    cli_off = rva_to_offset(pe, cli_rva)
    resource_rva, resource_size = struct.unpack_from('<II', pe, cli_off + 24)
    resource_off = rva_to_offset(pe, resource_rva)
    blob = pe[resource_off:resource_off + resource_size]
    if len(blob) != resource_size or len(blob) < 4:
        raise ValueError('Truncated .NET resources')
    encrypted_len = struct.unpack_from('<I', blob, 0)[0]
    if encrypted_len + 4 > len(blob):
        raise ValueError('Truncated managed resource')
    return blob[4:4 + encrypted_len]


def save(out: Path, name: str, data: bytes) -> None:
    if not data.startswith(b'MZ'):
        raise ValueError(f'{name} did not unpack to an MZ executable')
    dst = out / name
    with dst.open('xb') as fp:
        fp.write(data)
    dst.chmod(0o600)
    digest = hashlib.sha1(data).hexdigest()
    print(f'{name}: {len(data)} bytes, SHA-1 {digest}')
    if digest != EXPECTED_SHA1[name]:
        print('WARNING: unexpected hash; stop and recheck the source sample')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('batch', type=Path, help='Exported 5c74.bat, dwm.bat or temp_993805.bat')
    parser.add_argument('--out', type=Path, required=True, help='New output directory (must not exist)')
    args = parser.parse_args()
    source = args.batch.read_text(encoding='utf-8', errors='replace')
    line = next((line for line in source.splitlines() if line.startswith(':: ')), None)
    if line is None:
        parser.error('No :: data marker found in batch')
    blobs = line[3:].split('\\')
    if len(blobs) != 2:
        parser.error(f'Expected two backslash-separated ciphertexts; got {len(blobs)}')
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    recovered = []
    for blob in blobs:
        recovered.append(aes_gzip(base64.b64decode(blob, validate=True), LAYER1_KEY, LAYER1_IV))
    save(args.out, 'payload_0_unpacked.bin', recovered[0])
    save(args.out, 'payload_1_unpacked.bin', recovered[1])
    encrypted_resource = dotnet_resource(recovered[1])
    final_pe = aes_gzip(encrypted_resource, LAYER2_KEY, LAYER2_IV)
    save(args.out, 'payload_1_embedded_unpacked.bin', final_pe)
    print('Static recovery complete. DO NOT execute recovered PE files.')


if __name__ == '__main__':
    main()

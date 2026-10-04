# Optional reversing notes

## Why a normal module dump failed

Volatility identified `singularity` as a hidden module, but both automatic reconstruction attempts failed:

```bash
mkdir -p singularity_dump
/usr/local/bin/vol3 -f dump_srv.mem -s . -o singularity_dump \
  linux.malware.hidden_modules.Hidden_modules --dump
```

and:

```bash
/usr/local/bin/vol3 -f dump_srv.mem -s . -o singularity_extract \
  linux.module_extract.ModuleExtract --base 0xffffc0b35000
```

The same result occurred when attempting the module-structure address `0xffffc0b42640`.

Because no valid ELF could be reconstructed, the mapped module region was carved manually.

---

## Manual carving with Volshell

Volshell was launched from the Volatility virtual environment:

```bash
/opt/volatility3/bin/volshell -f dump_srv.mem -s . -l
```

Available layers:

```python
list(context.layers)
# ['base_layer', 'memory_layer', 'layer_name']
```

A small read at the module base succeeded:

```python
context.layers['layer_name'].read(0xffffc0b35000, 16)
# b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
```

Reading the complete `0x19000`-byte range without padding hit an unmapped page. Volatility's `pad=True` option was therefore used:

```python
data = context.layers['layer_name'].read(
    0xffffc0b35000,
    0x19000,
    pad=True
)
len(data)
# 102400

open('singularity.raw', 'wb').write(data)
# 102400
```

The resulting file was a raw memory region rather than a reconstructed ELF.

---

## String validation

Before importing the carve into a disassembler, targeted strings confirmed that useful rootkit content had been recovered:

```bash
strings -a singularity.raw | \
  grep -i -E 'singularity|become_root|hidden_pid|hook_kill|icmp' | head -50
```

Examples:

```text
singularity
singularity_exit
hook_kill
hook_icmp_rcv
orig_icmp_rcv
hiding_icmp_init
become_root_init
become_root_exit
is_hidden_pid
add_hidden_pid
hidden_pids
```

---

## Ghidra import

The raw image was imported with:

| Setting | Value |
|---|---|
| Format | Raw Binary |
| Processor | x86 |
| Size | 64-bit |
| Endian | Little |
| Compiler | gcc |
| Image base | `0xffffffffc0b35000` |

Volatility displayed the module base in its 48-bit virtual-address form `0xffffc0b35000`. In Ghidra the address was sign-extended to the canonical x86-64 kernel address `0xffffffffc0b35000`.

The same applies to the centralized callback:

- Volatility form: `0xffffc0b3aac0`
- Canonical form: `0xffffffffc0b3aac0`

Ghidra identified **74 candidate functions** in the carved region.

---

## Central ftrace callback

The function at `0xffffffffc0b3aac0` was reviewed in assembly.

The code:

- Preserves the incoming `RSI` value.
- Iterates over structures separated by `0x48` bytes.
- Reads a base address and size from each structure.
- Compares the preserved address against those ranges.
- On the redirect path, copies a target value into the supplied register context.

This behavior is consistent with a common ftrace thunk design: calls originating from the rootkit's own code ranges are allowed through to prevent recursion, while external calls can be redirected to a hook handler.

The Ghidra decompiler reported bad-instruction/control-flow warnings. That is expected for this artifact because the input is a **raw memory carve with missing pages padded by zeroes**, not the original kernel-module ELF with section metadata and relocations.

---

## Practical conclusion

The carve was sufficient to validate that executable rootkit code and useful function artifacts remained resident in memory. A full source-level reconstruction was not necessary to solve the Sherlock, so reversing was stopped after confirming the ftrace callback architecture.

The carved `singularity.raw` is intentionally not committed to this public repository; the reproducible extraction procedure is documented instead.

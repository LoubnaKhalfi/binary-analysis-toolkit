# Binary Analysis Toolkit

A static analysis toolkit for ELF and PE binaries. Parses headers, disassembles code, extracts strings, and detects packed/obfuscated sections via entropy analysis — the same fundamentals behind tools like pestudio, Detect-It-Easy, and Cutter.

---

## Features

| Module | Description |
|---|---|
| **Static** | File type, architecture, entry point, sections, imports, exports, symbols, MD5/SHA256 |
| **Disassembly** | Disassembles `.text` section using Capstone |
| **Strings** | Extracts ASCII and UTF-16LE strings with offsets |
| **Entropy** | Per-section Shannon entropy — flags packed/encrypted regions |
| **Report** | Exports full analysis to JSON or Markdown |

---

## Requirements

- Python 3.8+
- `libmagic` system library:
  ```bash
  # Debian/Ubuntu
  sudo apt install libmagic1

  # macOS
  brew install libmagic
  ```

- Python dependencies:
  ```bash
  pip install -r requirements.txt
  ```

---

## Usage

```bash
python analyze.py <binary> [options]
```

| Option | Description |
|---|---|
| `--disasm` | Disassemble `.text` section |
| `--strings` | Extract ASCII/UTF-16LE strings |
| `--entropy` | Run entropy analysis per section |
| `--all` | Run all modules |
| `--report json` | Export report as JSON |
| `--report markdown` | Export report as Markdown |

---

## Examples

```bash
# Basic static info
python analyze.py /bin/ls

# Full analysis
python analyze.py /bin/ls --all

# Disassembly only
python analyze.py target.elf --disasm

# Analyze PE binary and export report
python analyze.py malware.exe --all --report markdown

# Check if binary is packed (entropy)
python analyze.py suspicious.elf --entropy
```

---

## Sample Output

```
[*] Analyzing: /bin/ls
==================================================
[+] Type     : ELF 64-bit LSB pie executable, x86-64
[+] Format   : ELF
[+] MD5      : d41d8cd98f00b204e9800998ecf8427e
[+] SHA256   : e3b0c44298fc1c149afbf4c8996fb924...
[+] Size     : 142848 bytes
[+] Arch     : x64
[+] Entry    : 0x6d30
[+] Sections : 31
[+] Imports  : 187

[Entropy] Section analysis

  Section          Size     Entropy  Status
  ----------------  --------  --------  ------------------------------------
  .text            93456     6.1023  ✅ NORMAL
  .rodata          28672     4.8871  ✅ NORMAL
  .data            3840      3.2910  ✅ NORMAL

[Disassembly] .text @ 0x6d30 (first 100 instructions)

  0x6d30:  endbr64
  0x6d34:  xor      ebp, ebp
  0x6d36:  mov      r9, rdx
  ...
```

---

## How It Works

- **ELF parsing** via `pyelftools` — reads section headers, symbol tables, dynamic linking info
- **PE parsing** via `pefile` — reads imports, exports, section table, timestamps
- **Disassembly** via `capstone` — the same engine used in GDB, radare2, and many others
- **Entropy** uses Shannon entropy formula — values above ~7.2 strongly suggest packing or encryption
- **String extraction** uses regex over raw bytes — finds both ASCII and UTF-16LE encoded strings

---

## Entropy Reference

| Range | Meaning |
|---|---|
| 0 – 4.0 | Low entropy — plain text, sparse data |
| 4.0 – 6.0 | Normal executable code |
| 6.0 – 7.2 | Possibly obfuscated |
| 7.2 – 8.0 | Packed, encrypted, or compressed |

---

## Supported Formats

- ✅ ELF (Linux/Unix binaries)
- ✅ PE / PE32+ (Windows executables and DLLs)


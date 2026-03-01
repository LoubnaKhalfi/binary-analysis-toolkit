import json
import os
from datetime import datetime

def export(results, binary_path, fmt):
    base = os.path.splitext(os.path.basename(binary_path))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{base}_report_{timestamp}.{fmt if fmt == 'json' else 'md'}"

    if fmt == "json":
        with open(filename, "w") as f:
            json.dump(results, f, indent=2)

    elif fmt == "markdown":
        with open(filename, "w") as f:
            s = results.get("static", {})
            f.write(f"# Binary Analysis Report\n\n")
            f.write(f"**File:** `{binary_path}`  \n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n\n")

            f.write(f"## Hashes\n\n")
            h = s.get("hashes", {})
            f.write(f"| Hash | Value |\n|---|---|\n")
            f.write(f"| MD5 | `{h.get('md5')}` |\n")
            f.write(f"| SHA256 | `{h.get('sha256')}` |\n")
            f.write(f"| Size | {h.get('size')} bytes |\n\n")

            f.write(f"## Static Info\n\n")
            f.write(f"| Field | Value |\n|---|---|\n")
            for k in ["type", "arch", "entry_point", "endianness"]:
                if k in s:
                    f.write(f"| {k} | `{s[k]}` |\n")

            f.write(f"\n## Sections\n\n| Name | Offset | Size |\n|---|---|---|\n")
            for sec in s.get("sections", []):
                f.write(f"| {sec['name']} | {sec['offset']} | {sec['size']} |\n")

            if "entropy" in results:
                f.write(f"\n## Entropy\n\n| Section | Size | Entropy | Status |\n|---|---|---|---|\n")
                for e in results["entropy"]:
                    f.write(f"| {e['section']} | {e['size']} | {e['entropy']} | {e['status']} |\n")

            if "strings" in results:
                f.write(f"\n## Strings (first 50)\n\n```\n")
                for s in results["strings"][:50]:
                    f.write(f"{s['offset']}  [{s['encoding']}]  {s['value']}\n")
                f.write("```\n")

            if "disassembly" in results:
                f.write(f"\n## Disassembly (.text)\n\n```asm\n")
                for insn in results["disassembly"]:
                    f.write(f"{insn['address']}:  {insn['mnemonic']:<8} {insn['op_str']}\n")
                f.write("```\n")

    print(f"\n[+] Report saved: {filename}")

def print_summary(results):
    s = results.get("static", {})
    imports = s.get("imports", [])
    if imports:
        print(f"\n[Imports] ({len(imports)} total, showing first 20)")
        for i in imports[:20]:
            print(f"  {i}")
    symbols = s.get("symbols", [])
    if symbols:
        print(f"\n[Symbols] ({len(symbols)} total, showing first 20)")
        for sym in symbols[:20]:
            print(f"  {sym}")

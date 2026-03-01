import math

def _entropy(data):
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())

def _flag(e):
    if e > 7.2:
        return "⚠️  HIGH (packed/encrypted/compressed)"
    elif e > 6.0:
        return "🔶 MEDIUM (possibly obfuscated)"
    return "✅ NORMAL"

def _sections_elf(path):
    from elftools.elf.elffile import ELFFile
    sections = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for s in elf.iter_sections():
            if s.header.sh_size > 0:
                sections.append((s.name, s.data()))
    return sections

def _sections_pe(path):
    import pefile
    pe = pefile.PE(path)
    return [
        (s.Name.decode(errors="ignore").strip("\x00"), s.get_data())
        for s in pe.sections
    ]

def analyze(path, ftype):
    sections = _sections_elf(path) if ftype == "elf" else _sections_pe(path)
    results = []

    print(f"\n[Entropy] Section analysis\n")
    print(f"  {'Section':<16} {'Size':>8}  {'Entropy':>8}  Status")
    print(f"  {'-'*16}  {'-'*8}  {'-'*8}  {'-'*36}")

    for name, data in sections:
        e = _entropy(data)
        flag = _flag(e)
        print(f"  {name:<16} {len(data):>8}  {e:>8.4f}  {flag}")
        results.append({"section": name, "size": len(data), "entropy": round(e, 4), "status": flag})

    return results

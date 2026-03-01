import re

MIN_LENGTH = 4

def analyze(path, min_len=MIN_LENGTH):
    with open(path, "rb") as f:
        data = f.read()

    # ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    # UTF-16 LE strings
    utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")

    results = []

    for m in ascii_pattern.finditer(data):
        results.append({
            "offset": hex(m.start()),
            "encoding": "ascii",
            "value": m.group().decode()
        })

    for m in utf16_pattern.finditer(data):
        try:
            decoded = m.group().decode("utf-16-le")
            results.append({
                "offset": hex(m.start()),
                "encoding": "utf-16le",
                "value": decoded
            })
        except Exception:
            pass

    print(f"\n[Strings] Found {len(results)} strings (min length: {min_len})\n")
    for s in results[:50]:  # print first 50
        print(f"  {s['offset']}  [{s['encoding']}]  {s['value']}")
    if len(results) > 50:
        print(f"  ... and {len(results) - 50} more (use --report to export all)")

    return results

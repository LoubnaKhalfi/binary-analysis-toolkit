import os
import hashlib
import magic

def _hash(path):
    with open(path, "rb") as f:
        data = f.read()
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size":   len(data)
    }

def _detect_type(path):
    mime = magic.from_file(path)
    if "ELF" in mime:
        return "elf"
    elif "PE32" in mime or "MS-DOS" in mime:
        return "pe"
    return "unknown"

def _parse_elf(path):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    with open(path, "rb") as f:
        elf = ELFFile(f)
        info = {
            "arch":         elf.get_machine_arch(),
            "entry_point":  hex(elf.header.e_entry),
            "endianness":   "little" if elf.little_endian else "big",
            "type":         elf.header.e_type,
            "sections":     [],
            "symbols":      [],
            "imports":      []
        }
        for s in elf.iter_sections():
            info["sections"].append({
                "name":    s.name,
                "offset":  hex(s.header.sh_offset),
                "size":    s.header.sh_size,
                "flags":   hex(s.header.sh_flags)
            })
            if isinstance(s, SymbolTableSection):
                for sym in s.iter_symbols():
                    if sym.name:
                        info["symbols"].append(sym.name)

        # dynamic imports
        dyn = elf.get_section_by_name(".dynstr")
        if dyn:
            info["imports"] = [
                e for e in dyn.data().decode(errors="ignore").split("\x00") if e
            ]
    return info

def _parse_pe(path):
    import pefile
    pe = pefile.PE(path)
    info = {
        "arch":        "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86",
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "timestamp":   pe.FILE_HEADER.TimeDateStamp,
        "sections":    [],
        "imports":     [],
        "exports":     []
    }
    for s in pe.sections:
        info["sections"].append({
            "name":   s.Name.decode(errors="ignore").strip("\x00"),
            "offset": hex(s.PointerToRawData),
            "size":   s.SizeOfRawData,
            "vaddr":  hex(s.VirtualAddress)
        })
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                name = imp.name.decode() if imp.name else f"ord({imp.ordinal})"
                info["imports"].append(f"{lib.dll.decode()}::{name}")
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                info["exports"].append(exp.name.decode())
    return info

def analyze(path):
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        return None

    ftype = _detect_type(path)
    print(f"[+] Type     : {magic.from_file(path)}")
    print(f"[+] Format   : {ftype.upper()}")

    hashes = _hash(path)
    print(f"[+] MD5      : {hashes['md5']}")
    print(f"[+] SHA256   : {hashes['sha256']}")
    print(f"[+] Size     : {hashes['size']} bytes")

    info = {"type": ftype, "hashes": hashes, "file": path}

    if ftype == "elf":
        info.update(_parse_elf(path))
    elif ftype == "pe":
        info.update(_parse_pe(path))
    else:
        print("[!] Unsupported format (only ELF/PE supported)")
        return None

    print(f"[+] Arch     : {info.get('arch')}")
    print(f"[+] Entry    : {info.get('entry_point')}")
    print(f"[+] Sections : {len(info.get('sections', []))}")
    print(f"[+] Imports  : {len(info.get('imports', []))}")

    return info

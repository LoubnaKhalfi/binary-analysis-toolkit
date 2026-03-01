import capstone

SECTION_NAME = {
    "elf": ".text",
    "pe":  ".text"
}

def _get_text_section_elf(path):
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".text")
        if not sec:
            return None, None
        return sec.data(), sec.header.sh_addr

def _get_text_section_pe(path):
    import pefile
    pe = pefile.PE(path)
    for s in pe.sections:
        if b".text" in s.Name:
            return s.get_data(), pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
    return None, None

def analyze(path, ftype, max_instructions=100):
    if ftype == "elf":
        code, base_addr = _get_text_section_elf(path)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif ftype == "pe":
        code, base_addr = _get_text_section_pe(path)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    else:
        return []

    if not code:
        print("[!] No .text section found")
        return []

    md.detail = True
    instructions = []
    print(f"\n[Disassembly] .text @ {hex(base_addr)} (first {max_instructions} instructions)\n")

    for i, insn in enumerate(md.disasm(code, base_addr)):
        if i >= max_instructions:
            break
        line = f"  {hex(insn.address)}:  {insn.mnemonic:<8} {insn.op_str}"
        print(line)
        instructions.append({
            "address": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str
        })

    return instructions

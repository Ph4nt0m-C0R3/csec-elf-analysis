"""Bounded raw disassembly of the ELF .text section using Capstone."""

from __future__ import annotations

try:
    import capstone
except ImportError:  # The report remains usable if the optional native wheel fails.
    capstone = None
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from .elf_parser import ensure_before
from .functions import RISKY_FUNCTIONS


def analyze_disassembly(elf, deadline: float, maximum: int) -> dict:
    ensure_before(deadline)
    if capstone is None:
        return _unavailable(
            "Capstone is not installed for this Python platform. Install the "
            "requirements with a standard python.org Windows Python or Kali Python."
        )
    section = elf.get_section_by_name(".text")
    if section is None:
        return _unavailable("The ELF file has no readable .text section.")

    engine = _engine_spec(elf)
    if engine is None:
        machine = str(elf.header["e_machine"])
        return _unavailable(
            f"Capstone mapping is not available for architecture {machine}."
        )

    architecture, mode, label = engine
    code = section.data()
    start_address = int(section.header["sh_addr"])
    disassembler = capstone.Cs(architecture, mode)
    disassembler.detail = True
    symbol_addresses = _symbol_addresses(elf)
    instructions = []
    risks = []
    truncated = False

    for index, instruction in enumerate(
        disassembler.disasm(code, start_address, count=maximum + 1)
    ):
        if index % 50 == 0:
            ensure_before(deadline)
        if index >= maximum:
            truncated = True
            break
        target_address = _direct_target(instruction)
        target_name = symbol_addresses.get(target_address)
        risk = _instruction_risk(instruction, target_name)
        if risk:
            risks.append(
                {
                    "address": f"0x{instruction.address:016x}",
                    "symbol": target_name,
                    **risk,
                }
            )
        instructions.append(
            {
                "address": f"0x{instruction.address:016x}",
                "bytes": " ".join(f"{byte:02x}" for byte in instruction.bytes),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
                "symbol": symbol_addresses.get(instruction.address),
                "target_symbol": target_name,
                "risk": risk,
            }
        )

    ensure_before(deadline)
    return {
        "available": True,
        "engine": "Capstone",
        "architecture": label,
        "section": ".text",
        "start_address": f"0x{start_address:x}",
        "section_size": len(code),
        "instructions": instructions,
        "instruction_count": len(instructions),
        "risks": risks,
        "risk_count": len(risks),
        "truncated": truncated,
        "note": (
            "This is raw linear assembly disassembly. It is not decompiled C, "
            "does not identify every function, and may interpret embedded data as code."
        ),
    }


def _symbol_addresses(elf) -> dict[int, str]:
    addresses: dict[int, str] = {}
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            address = int(symbol.entry["st_value"])
            if address and symbol.name:
                addresses.setdefault(address, symbol.name.split("@", 1)[0])

    plt = elf.get_section_by_name(".plt.sec")
    has_reserved_entry = False
    if plt is None:
        plt = elf.get_section_by_name(".plt")
        has_reserved_entry = True
    if plt is None:
        return addresses

    entry_size = int(plt.header["sh_entsize"]) or 16
    base = int(plt.header["sh_addr"])
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        if "plt" not in section.name:
            continue
        symbols = elf.get_section(section.header["sh_link"])
        for index, relocation in enumerate(section.iter_relocations()):
            symbol_index = relocation.entry["r_info_sym"]
            symbol = symbols.get_symbol(symbol_index)
            offset = index + (1 if has_reserved_entry else 0)
            addresses[base + offset * entry_size] = symbol.name.split("@", 1)[0]
    return addresses


def _direct_target(instruction) -> int | None:
    if instruction.mnemonic not in {"call", "bl", "jal", "jalr"}:
        return None
    if not instruction.operands:
        return None
    operand = instruction.operands[0]
    if operand.type == capstone.CS_OP_IMM:
        return int(operand.imm)
    return None


def _instruction_risk(instruction, target_name: str | None) -> dict | None:
    if target_name in RISKY_FUNCTIONS:
        severity, explanation = RISKY_FUNCTIONS[target_name]
        return {
            "severity": severity,
            "title": f"Call to {target_name}() requires review",
            "detail": explanation,
        }
    if instruction.mnemonic in {"syscall", "sysenter", "svc"}:
        return {
            "severity": "medium",
            "title": "Direct operating-system call boundary",
            "detail": (
                "Review the surrounding function to confirm the operation and "
                "whether untrusted data controls its arguments."
            ),
        }
    return None


def _engine_spec(elf) -> tuple[int, int, str] | None:
    if capstone is None:
        return None
    machine = str(elf.header["e_machine"])
    endian = (
        capstone.CS_MODE_LITTLE_ENDIAN
        if elf.little_endian
        else capstone.CS_MODE_BIG_ENDIAN
    )
    if machine == "EM_X86_64":
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64, "x86-64"
    if machine == "EM_386":
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32, "x86"
    if machine == "EM_ARM":
        return capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | endian, "ARM"
    if machine == "EM_AARCH64":
        return capstone.CS_ARCH_ARM64, endian, "AArch64"
    if machine == "EM_MIPS":
        width = (
            capstone.CS_MODE_MIPS64
            if elf.elfclass == 64
            else capstone.CS_MODE_MIPS32
        )
        return capstone.CS_ARCH_MIPS, width | endian, f"MIPS{elf.elfclass}"
    if machine == "EM_RISCV" and hasattr(capstone, "CS_ARCH_RISCV"):
        width = (
            capstone.CS_MODE_RISCV64
            if elf.elfclass == 64
            else capstone.CS_MODE_RISCV32
        )
        return capstone.CS_ARCH_RISCV, width, f"RISC-V {elf.elfclass}"
    return None


def _unavailable(reason: str) -> dict:
    return {
        "available": False,
        "engine": "Capstone",
        "architecture": "Unsupported or unavailable",
        "section": ".text",
        "start_address": None,
        "section_size": 0,
        "instructions": [],
        "instruction_count": 0,
        "risks": [],
        "risk_count": 0,
        "truncated": False,
        "note": reason,
    }

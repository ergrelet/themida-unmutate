from binaryninja import BinaryView, BinaryReader, BinaryWriter  # type:ignore

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core import parse_asm
from miasm.core.asmblock import AsmCFG, asm_resolve_final
from miasm.core.locationdb import LocationDB
from themida_unmutate.miasm_utils import MiasmContext, MiasmFunctionInterval


def get_binary_data(bv: BinaryView) -> bytearray:
    """
    Retrieve binary data from `bv` as single `bytearray`.
    Note: spaces between sections are replaced with 0s.
    """
    # Sort sections by start address
    sections = list(bv.sections.values())
    sorted_section = sorted(sections, key=lambda s: s.start)

    br = BinaryReader(bv)
    last_section_address = bv.original_base
    exe_data = bytearray()
    for section in sorted_section:
        # Pad with zeroes
        padding_size = section.start - last_section_address
        exe_data += b"\x00" * padding_size
        exe_data += br.read(section.length, section.start)
        last_section_address = section.start + section.length

    return exe_data


def create_miasm_context(arch: str, binary_base_address: int, binary_data: bytearray) -> MiasmContext:
    """
    Create `MiasmContext` from a `bytearray`, given the architecture and base address.
    """
    loc_db = LocationDB()
    machine = Machine(arch)
    assert machine.dis_engine is not None
    container = Container.from_string(binary_data, loc_db, addr=binary_base_address)
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    lifter = machine.lifter(loc_db)

    return MiasmContext(loc_db, container, machine, mdis, lifter)


def rebuild_simplified_binary(
    miasm_ctx: MiasmContext,
    func_addr_to_simplified_cfg: dict[int, tuple[AsmCFG, MiasmFunctionInterval]],
    bv: BinaryView,
) -> None:
    """
    Regenerate simplified machine code and patch the binary in place via `bv`.
    """
    bw = BinaryWriter(bv)

    # Reassemble simplified AsmCFGs
    original_to_simplified: dict[int, int] = {}
    for protected_func_addr, val in func_addr_to_simplified_cfg.items():
        simplified_asmcfg, orignal_asmcfg_interval = val

        # Unpin blocks to be able to relocate the CFG
        head = simplified_asmcfg.heads()[0]
        for asm_block in simplified_asmcfg.blocks:
            miasm_ctx.loc_db.unset_location_offset(asm_block.loc_key)

        # Start rewriting at the first part of the interval (i.e., at the start
        # of the mutated code)
        target_addr: int = orignal_asmcfg_interval.intervals[0][0]
        # Unpin loc_key if it's pinned
        original_loc = miasm_ctx.loc_db.get_offset_location(target_addr)
        if original_loc is not None:
            miasm_ctx.loc_db.unset_location_offset(original_loc)

        # Relocate the function's entry block
        miasm_ctx.loc_db.set_location_offset(head, target_addr)

        # Generate the simplified machine code
        new_section_patches = asm_resolve_final(miasm_ctx.mdis.arch,
                                                simplified_asmcfg,
                                                dst_interval=orignal_asmcfg_interval)

        # Apply patches
        for address, data in new_section_patches.items():
            bw.write(bytes(data), address)

        # Associate original addr to simplified addr
        original_to_simplified[protected_func_addr] = min(new_section_patches.keys())

    # Redirect functions to their simplified versions
    protected_function_addrs = func_addr_to_simplified_cfg.keys()
    for target_addr in protected_function_addrs:
        # Generate a single-block AsmCFG with a JMP to the simplified version
        simplified_func_addr = original_to_simplified[target_addr]
        original_loc_str = f"loc_{target_addr:x}"
        jmp_unmut_instr_str = f"{original_loc_str}:\nJMP 0x{simplified_func_addr:x}"
        jmp_unmut_asmcfg = parse_asm.parse_txt(miasm_ctx.mdis.arch, miasm_ctx.mdis.attrib, jmp_unmut_instr_str,
                                               miasm_ctx.mdis.loc_db)

        # Unpin loc_key if it's pinned
        original_loc = miasm_ctx.loc_db.get_offset_location(target_addr)
        if original_loc is not None:
            miasm_ctx.loc_db.unset_location_offset(original_loc)

        # Relocate the newly created block and generate machine code
        original_loc = miasm_ctx.loc_db.get_name_location(original_loc_str)
        miasm_ctx.loc_db.set_location_offset(original_loc, target_addr)
        new_jmp_patches = asm_resolve_final(miasm_ctx.mdis.arch, jmp_unmut_asmcfg)

        # Apply patches
        for address, data in new_jmp_patches.items():
            bw.write(bytes(data), address)

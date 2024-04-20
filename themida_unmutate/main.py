from argparse import ArgumentParser, Namespace
from typing import Optional

import lief
from miasm.core import parse_asm
from miasm.core.asmblock import AsmCFG, asm_resolve_final, bbl_simplifier
from miasm.core.interval import interval

from themida_unmutate.logging import setup_logger, LOGGER
from themida_unmutate.miasm_utils import MiasmContext, MiasmFunctionInterval
from themida_unmutate.symbolic_execution import disassemble_and_simplify_functions
from themida_unmutate.unwrapping import unwrap_function

NEW_SECTION_NAME = ".unmut"
NEW_SECTION_MAX_SIZE = 2**16


def entry_point() -> None:
    # Parse command-line arguments
    args = parse_arguments()

    # Setup logging
    setup_logger(args.verbose)

    # Setup disassembler and lifter
    miasm_ctx = MiasmContext.from_binary_file(args.protected_binary)

    # Resolve mutated functions' addresses if needed
    protected_func_addrs = list(map(lambda addr: int(addr, 0), args.addresses))
    if not args.no_trampoline:
        LOGGER.info("Resolving mutated's functions' addresses...")
        mutated_func_addrs = unwrap_functions(miasm_ctx, protected_func_addrs)
    else:
        # No trampolines to take care of, use target addresses directly
        mutated_func_addrs = protected_func_addrs

    # Disassemble mutated functions and simplify them
    LOGGER.info("Deobfuscating mutated functions...")
    simplified_func_asmcfgs = disassemble_and_simplify_functions(miasm_ctx, mutated_func_addrs)

    # Map protected functions' addresses to their corresponding simplified `AsmCFG`
    func_addr_to_simplified_cfg = {
        protected_func_addrs[i]: asm_cfg
        for i, asm_cfg in enumerate(simplified_func_asmcfgs)
    }

    # Rewrite the protected binary with simplified functions
    LOGGER.info("Rebuilding binary file...")
    rebuild_simplified_binary(miasm_ctx, func_addr_to_simplified_cfg, args.protected_binary, args.output,
                              args.reassemble_in_place)

    LOGGER.info("Done! You can find your deobfuscated binary at '%s'" % args.output)


def parse_arguments() -> Namespace:
    """
    Parse command-line arguments.
    """
    parser = ArgumentParser(description="Automatic deobfuscation tool for Themida's mutation-based protection")
    parser.add_argument("protected_binary", help="Protected binary path")
    parser.add_argument("-a", "--addresses", nargs='+', help="Addresses of the functions to deobfuscate", required=True)
    parser.add_argument("-o", "--output", help="Output binary path", required=True)
    parser.add_argument("--no-trampoline", action='store_true', help="Disable function unwrapping")
    parser.add_argument("--reassemble-in-place",
                        action='store_true',
                        help="Rewrite simplified code over the mutated code"
                        "rather than in a new code section")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose logging")

    return parser.parse_args()


def unwrap_functions(miasm_ctx: MiasmContext, target_function_addrs: list[int]) -> list[int]:
    """
    Resolve mutated function's addresses from original function addresses.
    """
    mutated_func_addrs: list[int] = []
    for addr in target_function_addrs:
        LOGGER.debug("Resolving mutated code portion address for 0x%x..." % addr)
        mutated_code_addr = unwrap_function(miasm_ctx, addr)
        if mutated_code_addr == addr:
            raise Exception("Failure to unwrap function")

        LOGGER.info("Function at 0x%x jumps to 0x%x" % (addr, mutated_code_addr))
        mutated_func_addrs.append(mutated_code_addr)

    return mutated_func_addrs


def rebuild_simplified_binary(
    miasm_ctx: MiasmContext,
    func_addr_to_simplified_cfg: dict[int, tuple[AsmCFG, MiasmFunctionInterval]],
    input_binary_path: str,
    output_binary_path: str,
    reassemble_in_place: bool,
) -> None:
    """
    Reassemble functions' `AsmCFG` and rewrite the input binary with simplified
    machine code.
    """
    if len(func_addr_to_simplified_cfg) == 0:
        raise ValueError("`protected_function_addrs` cannot be empty")

    if reassemble_in_place:
        __rebuild_simplified_binary_in_place(miasm_ctx, func_addr_to_simplified_cfg, input_binary_path,
                                             output_binary_path)
    else:
        __rebuild_simplified_binary_in_new_section(miasm_ctx, func_addr_to_simplified_cfg, input_binary_path,
                                                   output_binary_path)


def __rebuild_simplified_binary_in_new_section(
    miasm_ctx: MiasmContext,
    func_addr_to_simplified_cfg: dict[int, tuple[AsmCFG, MiasmFunctionInterval]],
    input_binary_path: str,
    output_binary_path: str,
) -> None:
    """
    Reassemble functions' `AsmCFG` and rewrite the input binary with simplified
    machine code in a new code section.
    """
    # Open the target binary with LIEF
    pe_obj = lief.PE.parse(input_binary_path)
    if pe_obj is None:
        raise Exception(f"Failed to parse PE '{input_binary_path}'")

    # Create a new code section
    unmut_section = lief.PE.Section([0] * NEW_SECTION_MAX_SIZE, NEW_SECTION_NAME,
                                    lief.PE.SECTION_CHARACTERISTICS.CNT_CODE.value
                                    | lief.PE.SECTION_CHARACTERISTICS.MEM_READ.value
                                    | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE.value)
    pe_obj.add_section(unmut_section)
    unmut_section = pe_obj.get_section(NEW_SECTION_NAME)
    unmut_section_base = pe_obj.imagebase + unmut_section.virtual_address

    # Reassemble simplified AsmCFGs
    original_to_simplified: dict[int, int] = {}
    next_min_offset_for_asm = 0
    unmut_section_patches: list[tuple[int, bytes]] = []
    for protected_func_addr, val in \
            func_addr_to_simplified_cfg.items():
        simplified_asmcfg, _ = val
        # Simplify CFG further (by merging basic blocks when possible)
        simplified_asmcfg = bbl_simplifier(simplified_asmcfg)

        # Unpin blocks to be able to relocate the whole CFG
        head = simplified_asmcfg.heads()[0]
        for ir_block in simplified_asmcfg.blocks:
            miasm_ctx.loc_db.unset_location_offset(ir_block.loc_key)

        # Relocate the function's entry block
        miasm_ctx.loc_db.set_location_offset(head, unmut_section_base + next_min_offset_for_asm)

        # Generate the simplified machine code
        new_section_patches = asm_resolve_final(
            miasm_ctx.mdis.arch,
            simplified_asmcfg,
            dst_interval=interval([(unmut_section_base + next_min_offset_for_asm,
                                    unmut_section_base + unmut_section.virtual_size - next_min_offset_for_asm)]))

        # Merge patches into the patch list
        for patch in new_section_patches.items():
            unmut_section_patches.append(patch)

        # Associate original addr to simplified addr
        original_to_simplified[protected_func_addr] = min(new_section_patches.keys())
        next_min_offset_for_asm = max(new_section_patches.keys()) - unmut_section_base + 15

    # Overwrite the new section's content
    new_section_size = next_min_offset_for_asm
    new_content = bytearray([0] * new_section_size)
    for addr, data in unmut_section_patches:
        offset = addr - unmut_section_base
        new_content[offset:offset + len(data)] = data
    unmut_section.content = memoryview(new_content)

    # Find the section containing the original function
    protected_function_addrs = func_addr_to_simplified_cfg.keys()
    text_section = __section_from_virtual_address(pe_obj, next(iter(protected_function_addrs)))
    assert text_section is not None

    # Redirect functions to their simplified versions
    unmut_jmp_patches: list[tuple[int, bytes]] = []
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

        # Merge patches into the patch list
        for patch in new_jmp_patches.items():
            unmut_jmp_patches.append(patch)

    # Apply patches
    text_section_base = pe_obj.imagebase + text_section.virtual_address
    text_section_bytes = bytearray(text_section.content)
    for addr, data in unmut_jmp_patches:
        offset = addr - text_section_base
        text_section_bytes[offset:offset + len(data)] = data
    text_section.content = memoryview(text_section_bytes)

    # Invoke the builder
    builder = lief.PE.Builder(pe_obj)
    builder.build()

    # Save the result
    builder.write(output_binary_path)


def __rebuild_simplified_binary_in_place(
    miasm_ctx: MiasmContext,
    func_addr_to_simplified_cfg: dict[int, tuple[AsmCFG, MiasmFunctionInterval]],
    input_binary_path: str,
    output_binary_path: str,
) -> None:
    """
    Reassemble functions' `AsmCFG` and rewrite the input binary with simplified
    machine code by overwriting the mutated code.
    """
    # Open the target binary with LIEF
    pe_obj = lief.PE.parse(input_binary_path)
    if pe_obj is None:
        raise Exception(f"Failed to parse PE '{input_binary_path}'")

    # Reassemble simplified AsmCFGs
    original_to_simplified: dict[int, int] = {}
    unmut_patches: list[tuple[int, bytes]] = []
    for protected_func_addr, val in \
            func_addr_to_simplified_cfg.items():
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

        # Merge patches into the patch list
        for patch in new_section_patches.items():
            unmut_patches.append(patch)

        # Associate original addr to simplified addr
        original_to_simplified[protected_func_addr] = min(new_section_patches.keys())

    # Find Themida's section
    themida_section = __section_from_virtual_address(pe_obj, target_addr)
    assert themida_section is not None

    # Overwrite Themida's section content
    themida_section_base = pe_obj.imagebase + themida_section.virtual_address
    new_content = bytearray(themida_section.content)
    for addr, data in unmut_patches:
        offset = addr - themida_section_base
        new_content[offset:offset + len(data)] = data
    themida_section.content = memoryview(new_content)

    # Find the section containing the original function
    protected_function_addrs = func_addr_to_simplified_cfg.keys()
    text_section = __section_from_virtual_address(pe_obj, next(iter(protected_function_addrs)))
    assert text_section is not None

    # Redirect functions to their simplified versions
    unmut_jmp_patches: list[tuple[int, bytes]] = []
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

        # Merge patches into the patch list
        for patch in new_jmp_patches.items():
            unmut_jmp_patches.append(patch)

    # Apply patches
    text_section_base = pe_obj.imagebase + text_section.virtual_address
    text_section_bytes = bytearray(text_section.content)
    for addr, data in unmut_jmp_patches:
        offset = addr - text_section_base
        text_section_bytes[offset:offset + len(data)] = data
    text_section.content = memoryview(text_section_bytes)

    # Invoke the builder
    builder = lief.PE.Builder(pe_obj)
    builder.build()

    # Save the result
    builder.write(output_binary_path)


def __section_from_virtual_address(lief_bin: lief.Binary, virtual_addr: int) -> Optional[lief.Section]:
    rva = virtual_addr - lief_bin.imagebase
    return __section_from_rva(lief_bin, rva)


def __section_from_rva(lief_bin: lief.Binary, rva: int) -> Optional[lief.Section]:
    for s in lief_bin.sections:
        if s.virtual_address <= rva < s.virtual_address + s.size:
            assert isinstance(s, lief.Section)
            return s

    return None


if __name__ == "__main__":
    entry_point()

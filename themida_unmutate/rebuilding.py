from typing import Optional

import lief
from miasm.core.asmblock import AsmCFG, asm_resolve_final, bbl_simplifier
from miasm.core.interval import interval

from themida_unmutate.miasm_utils import (MiasmContext, MiasmFunctionInterval, generate_code_redirect_patch,
                                          asm_resolve_final_in_place)

NEW_SECTION_NAME = ".unmut"
NEW_SECTION_MAX_SIZE = 2**16


def rebuild_simplified_binary(
    miasm_ctx: MiasmContext,
    func_addr_to_simplified_cfg: dict[int, tuple[int, AsmCFG, MiasmFunctionInterval]],
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
    func_addr_to_simplified_cfg: dict[int, tuple[int, AsmCFG, MiasmFunctionInterval]],
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
        original_code_addr, simplified_asmcfg, _ = val
        # Simplify CFG further (by merging basic blocks when possible)
        simplified_asmcfg = bbl_simplifier(simplified_asmcfg)

        # Unpin blocks to be able to relocate the whole CFG
        head = miasm_ctx.loc_db.get_offset_location(original_code_addr)
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

    # Redirect functions to their simplified versions
    protected_function_addrs = func_addr_to_simplified_cfg.keys()
    unmut_jmp_patches: list[tuple[int, bytes]] = []
    for target_addr in protected_function_addrs:
        # Generate a single-block AsmCFG with a JMP to the simplified version
        simplified_func_addr = original_to_simplified[target_addr]
        unmut_jmp_patch = generate_code_redirect_patch(miasm_ctx, target_addr, simplified_func_addr)
        unmut_jmp_patches.append(unmut_jmp_patch)

    # Find the section containing the original function
    text_section = __section_from_virtual_address(pe_obj, next(iter(protected_function_addrs)))
    assert text_section is not None

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
    func_addr_to_simplified_cfg: dict[int, tuple[int, AsmCFG, MiasmFunctionInterval]],
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
        original_code_addr, simplified_asmcfg, orignal_asmcfg_interval = val

        # Generate the simplified machine code
        new_section_patches = asm_resolve_final_in_place(miasm_ctx.loc_db,
                                                         miasm_ctx.mdis.arch,
                                                         simplified_asmcfg,
                                                         dst_interval=orignal_asmcfg_interval)

        # Merge patches into the patch list
        for patch in new_section_patches.items():
            unmut_patches.append(patch)

        # Associate original addr to simplified addr
        original_to_simplified[protected_func_addr] = original_code_addr

    # Find Themida's section
    mutated_func_addr = next(iter(original_to_simplified.values()))
    themida_section = __section_from_virtual_address(pe_obj, mutated_func_addr)
    assert themida_section is not None

    # Overwrite Themida's section content
    themida_section_base = pe_obj.imagebase + themida_section.virtual_address
    new_content = bytearray(themida_section.content)
    for addr, data in unmut_patches:
        offset = addr - themida_section_base
        new_content[offset:offset + len(data)] = data
    themida_section.content = memoryview(new_content)

    # Redirect functions to their simplified versions
    protected_function_addrs = func_addr_to_simplified_cfg.keys()
    unmut_jmp_patches: list[tuple[int, bytes]] = []
    for target_addr in protected_function_addrs:
        # Generate a single-block AsmCFG with a JMP to the simplified version
        simplified_func_addr = original_to_simplified[target_addr]
        unmut_jmp_patch = generate_code_redirect_patch(miasm_ctx, target_addr, simplified_func_addr)
        unmut_jmp_patches.append(unmut_jmp_patch)

    # Find the section containing the original function
    text_section = __section_from_virtual_address(pe_obj, next(iter(protected_function_addrs)))
    assert text_section is not None

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

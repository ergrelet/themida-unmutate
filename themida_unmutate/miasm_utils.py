from dataclasses import dataclass
from typing import Optional, Self

import miasm.expression.expression as m2_expr
import miasm.core.asmblock as m2_asmblock
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core import parse_asm
from miasm.core.asmblock import disasmEngine, AsmCFG, asm_resolve_final
from miasm.core.cpu import cls_mn
from miasm.core.interval import interval
from miasm.core.locationdb import LocationDB
from miasm.ir.ir import Lifter

MiasmFunctionInterval = interval


@dataclass
class MiasmContext:
    loc_db: LocationDB
    container: Container
    machine: Machine
    mdis: disasmEngine
    lifter: Lifter

    @classmethod
    def from_binary_file(cls, target_binary_path: str) -> Self:
        """
        Initialize our Miasm context from a binary file.
        """
        loc_db = LocationDB()
        with open(target_binary_path, 'rb') as target_binary:
            container = Container.from_stream(target_binary, loc_db)
        machine = Machine(container.arch)
        assert machine.dis_engine is not None

        mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
        lifter = machine.lifter(loc_db)

        return cls(loc_db, container, machine, mdis, lifter)

    @property
    def arch(self) -> str:
        return str(self.machine.name)


def expr_int_to_int(expr: m2_expr.ExprInt) -> int:
    int_size = expr.size
    is_signed = expr.arg >= 2**(int_size - 1)
    if is_signed:
        result = -(2**int_size - expr.arg)
    else:
        result = expr.arg

    return int(result)


def generate_code_redirect_patch(miasm_ctx: MiasmContext, src_addr: int, dst_addr: int) -> tuple[int, bytes]:
    """
    Generate a single-block AsmCFG with a JMP from `src_addr` to `dst_addr` and return the result patch.
    """
    X86_JMP_INSTRUCTION = "JMP"

    # Generate a single-block AsmCFG with a JMP to the simplified version
    original_loc_str = f"loc_{src_addr:x}"
    jmp_unmut_instr_str = f"{original_loc_str}:\n{X86_JMP_INSTRUCTION} 0x{dst_addr:x}"
    jmp_unmut_asmcfg = parse_asm.parse_txt(miasm_ctx.mdis.arch, miasm_ctx.mdis.attrib, jmp_unmut_instr_str,
                                           miasm_ctx.mdis.loc_db)

    # Unpin loc_key if it's pinned
    original_loc = miasm_ctx.loc_db.get_offset_location(src_addr)
    if original_loc is not None:
        miasm_ctx.loc_db.unset_location_offset(original_loc)

    # Relocate the newly created block and generate machine code
    original_loc = miasm_ctx.loc_db.get_name_location(original_loc_str)
    miasm_ctx.loc_db.set_location_offset(original_loc, src_addr)
    jmp_patches = asm_resolve_final(miasm_ctx.mdis.arch, jmp_unmut_asmcfg)
    jmp_patch: Optional[tuple[int, bytes]] = next(iter(jmp_patches.items()), None)
    assert jmp_patch is not None

    return jmp_patch


# Custom version of miasm's `asm_resolve_final` which works better for our
# in-place rewriting use case
def asm_resolve_final_in_place(loc_db: LocationDB,
                               mnemo: cls_mn,
                               asmcfg: AsmCFG,
                               dst_interval: Optional[interval] = None) -> dict[int, bytes]:
    """Resolve and assemble @asmcfg into interval
    @dst_interval"""

    asmcfg.sanity_check()

    merge_cnext_constraints(asmcfg)
    guess_blocks_size(loc_db, asmcfg, dst_interval)
    freeze_original_instructions(asmcfg)
    blockChains = m2_asmblock.group_constrained_blocks(asmcfg)
    resolved_blockChains = m2_asmblock.resolve_symbol(blockChains, asmcfg.loc_db, dst_interval)
    m2_asmblock.asmblock_final(mnemo, asmcfg, resolved_blockChains, True)
    patches = {}
    output_interval = interval()

    for block in asmcfg.blocks:
        offset = asmcfg.loc_db.get_location_offset(block.loc_key)
        for instr in block.lines:
            if not instr.data:
                # Empty line
                continue
            assert len(instr.data) == instr.l
            patches[offset] = instr.data
            instruction_interval = interval([(offset, offset + instr.l - 1)])
            if not (instruction_interval & output_interval).empty:
                raise RuntimeError("overlapping bytes %X" % int(offset))
            output_interval = output_interval.union(instruction_interval)
            instr.offset = offset
            offset += instr.l
    return patches


# This is a custom version of miasm's `guess_blocks_size` which simply reuse
# data from the original CFG's interval to compute true basic block sizes so
# that it properly fits inside of the destination interval
def guess_blocks_size(loc_db: LocationDB, asmcfg: AsmCFG, interval: interval) -> None:
    for block in asmcfg.blocks:
        # Compute block sizes from interval
        for start_addr, end_addr in interval.intervals:
            block_start_addr = loc_db.get_location_offset(block.loc_key)
            if start_addr <= block_start_addr <= end_addr:
                block.size = end_addr - block_start_addr
                block.max_size = block.size

        # Setup instructions for reassembly
        for instr in block.lines:
            if instr.b is None:
                # This is an instruction we synthesized, init with empty data
                instr.b = b""
                instr.l = 0


# Utility that we use to remove "c_next" constraints from AsmCFGs. This is
# needed because of the way Miasm treats pinned basic blocks when reassembling
# code.
def merge_cnext_constraints(asmcfg: AsmCFG) -> None:
    for block in asmcfg.blocks:
        cst_next = block.get_next()
        if cst_next is not None:
            next_block: m2_asmblock.AsmBlock = asmcfg.loc_key_to_block(cst_next)
            # Block pointed to by "c_next" constraints should only contain a single
            # JMP instruction
            assert (len(next_block.lines) == 1)
            assert (len(next_block.bto) == 1)

            # Replace "c_next" constraint with a "c_to" constraints taken from the
            # next instruction
            block.bto = set(filter(lambda cst: cst.c_t != m2_asmblock.AsmConstraint.c_next, block.bto))
            c_to = m2_asmblock.AsmConstraint(next(iter(next_block.bto)).loc_key)
            block.addto(c_to)
    # Update edges
    asmcfg.rebuild_edges()


# Very dirty utility to prevent Miasm from reassembling instructions that
# we didn't synthesize or relocate. This avoids the case where Miasm tries to
# reassemble an instruction and generates a longer machine instruction than the
# original one. This can lead to issues where the code we generate is too big
# to fit into the original basic blocks and thus in-place rewriting fails.
def freeze_original_instructions(asmcfg: AsmCFG) -> None:
    for bb in asmcfg.blocks:
        for i, instr in enumerate(bb.lines):
            # Check if the instruction as so machine code already associated
            # to it. Also avoid freezing JMP/JCC instructions.
            if instr.l > 0 and not str(instr).startswith("J"):
                # Generate an `AsmRaw` instruction that Miasm will keep as is
                bb.lines[i] = m2_asmblock.AsmRaw(instr.b)
                bb.lines[i].l = instr.l
                bb.lines[i].data = instr.b

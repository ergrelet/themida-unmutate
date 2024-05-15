from dataclasses import dataclass
from typing import Optional, Self

import miasm.expression.expression as m2_expr
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core import parse_asm
from miasm.core.asmblock import disasmEngine, asm_resolve_final
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

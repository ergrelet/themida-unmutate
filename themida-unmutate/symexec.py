import itertools
import sys
from typing import Optional, Tuple, Union

import lief
import miasm.expression.expression as m2_expr
from argparse import ArgumentParser
from miasm.core.cpu import instruction
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.asmblock import AsmCFG, disasmEngine, asm_resolve_final, bbl_simplifier
from miasm.core.interval import interval

NEW_SECTION_NAME = ".unmut"
NEW_SECTION_MAX_SIZE = 2**16
X86_BINARY_OPS_MAPPING = {
    "+": "ADD",
    "&": "AND",
    "|": "OR",
    "^": "XOR",
    "a>>": "SAR",
    ">>": "SHR",
    "<<": "SHL",
    ">>>": "ROR",
    "<<<": "ROL",
}
AMD64_SLICES_MAPPING = {
    # RAX
    "RAX[0:32]": "EAX",
    "RAX[0:16]": "AX",
    "RAX[8:16]": "AH",
    "RAX[0:8]": "AL",
    # RBX
    "RBX[0:32]": "EBX",
    "RBX[0:16]": "BX",
    "RBX[8:16]": "BH",
    "RBX[0:8]": "BL",
    # RCX
    "RCX[0:32]": "ECX",
    "RCX[0:16]": "CX",
    "RCX[8:16]": "CH",
    "RCX[0:8]": "CL",
    # RDX
    "RDX[0:32]": "EDX",
    "RDX[0:16]": "DX",
    "RDX[8:16]": "DH",
    "RDX[0:8]": "DL",
    # RSI
    "RSI[0:32]": "ESI",
    "RSI[0:16]": "SI",
    "RSI[8:16]": "SIH",
    "RSI[0:8]": "SIL",
    # RDI
    "RDI[0:32]": "EDI",
    "RDI[0:16]": "DI",
    "RDI[8:16]": "DIH",
    "RDI[0:8]": "DIL",
    # RSP
    "RSP[0:32]": "ESP",
    "RSP[0:16]": "SP",
    "RSP[8:16]": "SPH",
    "RSP[0:8]": "SPL",
    # RBP
    "RBP[0:32]": "EBP",
    "RBP[0:16]": "BP",
    "RBP[8:16]": "BPH",
    "RBP[0:8]": "BPL",
    # R8
    "R8[0:32]": "R8D",
    "R8[0:16]": "R8W",
    "R8[0:8]": "R8B",
    # R9
    "R9[0:32]": "R9D",
    "R9[0:16]": "R9W",
    "R9[0:8]": "R9B",
    # R10
    "R10[0:32]": "R10D",
    "R10[0:16]": "R10W",
    "R10[0:8]": "R10B",
    # R11
    "R11[0:32]": "R11D",
    "R11[0:16]": "R11W",
    "R11[0:8]": "R11B",
    # R12
    "R12[0:32]": "R12D",
    "R12[0:16]": "R12W",
    "R12[0:8]": "R12B",
    # R13
    "R13[0:32]": "R13D",
    "R13[0:16]": "R13W",
    "R13[0:8]": "R13B",
    # R14
    "R14[0:32]": "R14D",
    "R14[0:16]": "R14W",
    "R14[0:8]": "R14B",
    # R15
    "R15[0:32]": "R15D",
    "R15[0:16]": "R15W",
    "R15[0:8]": "R15B",
}


def main() -> None:
    parser = ArgumentParser("Automatic deobfuscation tool powered by Miasm")
    parser.add_argument("target", help="Target binary")
    parser.add_argument("addr", help="Target address")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--architecture", "-a", help="Force architecture")
    args = parser.parse_args()

    target_addr = int(args.addr, 0)

    loc_db = LocationDB()
    # This part focus on obtaining an IRCFG to transform
    cont = Container.from_stream(open(args.target, 'rb'), loc_db)
    machine = Machine(args.architecture if args.architecture else cont.arch)
    lifter = machine.lifter(loc_db)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
    asmcfg = mdis.dis_multiblock(target_addr)
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

    for loc_key, ir_block in ircfg.blocks.items():
        print(f"{loc_key}:")
        asm_block = asmcfg.loc_key_to_block(loc_key)
        if asm_block is None:
            # Some instructions such `idiv` generate multiple IR basic blocks from a single asm instruction, so we
            # skip these
            # print(str(ir_block))
            continue

        relevant_assignblks = ir_block.assignblks[:-1]
        relevant_blk_count = len(relevant_assignblks)
        # Only 1 or 2 instructions
        #   -> unmutated, no junk code -> no action needed -> keep first instruction as is
        if relevant_blk_count <= 2:
            print(ir_block.assignblks[0].instr)
            relocatable_instr = fix_rip_relative_instruction(
                asmcfg, asm_block.lines[0])
            asm_block.lines[0] = relocatable_instr
            continue

        reference_sb = SymbolicExecutionEngine(lifter)
        for assign_block in relevant_assignblks:
            reference_sb.eval_updt_assignblk(assign_block)
            # Forget dead stack slots
            reference_sb.del_mem_above_stack(lifter.sp)

        # Strip FLAGS register (as these are trashed by the mutation)
        strip_sym_flags(reference_sb)
        # print("Reference:")
        # print(reference_sb.dump())

        # More than 2 instructions but a single instruction replicates the symbolic state
        #   -> unmutated, junk code inserted -> keep the one instruction as is
        block_simplified = False
        for assignblk_subset in itertools.combinations(relevant_assignblks, 1):
            sb = SymbolicExecutionEngine(lifter)

            for assign_block in assignblk_subset:
                sb.eval_updt_assignblk(assign_block)
            reference_sb.del_mem_above_stack(lifter.sp)

            # Check if instruction replicates the symbolic state
            if reference_sb.get_state() == sb.get_state():
                for a in assignblk_subset:
                    print(a.instr)
                    # Update block asm block
                    relocatable_instr = fix_rip_relative_instruction(
                        asmcfg, a.instr)
                    asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                block_simplified = True
                break
        if block_simplified:
            continue

        # More than 2 instructions but no single instruction replicates the symbolic state
        #   -> mutated, junk code inserted -> try to "synthetize" instruction manually
        modified_variables = dict(reference_sb.modified())
        match len(modified_variables):
        # No assignment block: RET, JMP
            case 0:
                # Keep only the last instruction
                print(asm_block.lines[-1])
                asm_block.lines = [asm_block.lines[-1]]
                continue

            # 1 assignment block: MOV, n-ary operators
            case 1:
                dst, value = next(iter(modified_variables.items()))
                match type(value):
                    case m2_expr.ExprId | m2_expr.ExprMem | m2_expr.ExprInt:
                        # Assignation
                        # -> MOV
                        match type(dst):
                            case m2_expr.ExprId | m2_expr.ExprMem:
                                original_instr = handle_mov(mdis, dst, value)
                                if original_instr is not None:
                                    # Update block asm block
                                    relocatable_instr = fix_rip_relative_instruction(
                                        asmcfg, original_instr)
                                    asm_block.lines = [
                                        relocatable_instr, asm_block.lines[-1]
                                    ]
                                    continue
                                print(modified_variables)
                    case m2_expr.ExprOp:
                        # N-ary operation on native-size registers
                        # -> ADD/SUB/INC/DEC/AND/OR/XOR/NEG/NOT/ROL/ROR/SAR/SHL/SHR
                        original_instr = handle_nary_op(mdis, dst, value)
                        if original_instr is not None:
                            # Update block asm block
                            relocatable_instr = fix_rip_relative_instruction(
                                asmcfg, original_instr)
                            asm_block.lines = [
                                relocatable_instr, asm_block.lines[-1]
                            ]
                            continue
                        print(modified_variables)
                    case m2_expr.ExprCompose:
                        # MOV or n-ary operation on lower-sized registers
                        original_instr = handle_compose(mdis, dst, value)
                        if original_instr is not None:
                            # Update block asm block
                            relocatable_instr = fix_rip_relative_instruction(
                                asmcfg, original_instr)
                            asm_block.lines = [
                                relocatable_instr, asm_block.lines[-1]
                            ]
                            continue
                        print(modified_variables)

            # 2 assignment blocks
            # -> PUSH, POP, XCHG
            case 2:
                modified_variables_iter = iter(modified_variables.items())
                assignblk1 = next(modified_variables_iter)
                assignblk2 = next(modified_variables_iter)

                # PUSH
                original_instr = handle_push(mdis, assignblk1, assignblk2)
                if original_instr is not None:
                    # Update block asm block
                    relocatable_instr = fix_rip_relative_instruction(
                        asmcfg, original_instr)
                    asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                    continue
                # POP
                original_instr = handle_pop(mdis, assignblk1, assignblk2)
                if original_instr is not None:
                    # Update block asm block
                    relocatable_instr = fix_rip_relative_instruction(
                        asmcfg, original_instr)
                    asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                    continue
                # XCHG
                original_instr = handle_xchg(mdis, assignblk1, assignblk2)
                if original_instr is not None:
                    # Update block asm block
                    relocatable_instr = fix_rip_relative_instruction(
                        asmcfg, original_instr)
                    asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                    continue

        print("FIXME: unsupported instruction (or unmutated block?)")

    # Create a patched copy of the target
    pe_obj = lief.PE.parse(args.target)
    if pe_obj is None:
        print(f"Failed to parse PE '{args.target}'")
        sys.exit(-1)

    # Create a new code section
    unmut_section = lief.PE.Section(
        [0] * NEW_SECTION_MAX_SIZE, NEW_SECTION_NAME,
        lief.PE.SECTION_CHARACTERISTICS.CNT_CODE.value
        | lief.PE.SECTION_CHARACTERISTICS.MEM_READ.value
        | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE.value)
    pe_obj.add_section(unmut_section)
    unmut_section = pe_obj.get_section(NEW_SECTION_NAME)

    # Simplify CFG (by merging basic blocks when possible)
    asmcfg = bbl_simplifier(asmcfg)

    # Unpin blocks to be able to relocate the whole CFG
    image_base = pe_obj.imagebase
    section_base = image_base + unmut_section.virtual_address

    head = asmcfg.heads()[0]
    for ir_block in asmcfg.blocks:
        loc_db.unset_location_offset(ir_block.loc_key)
    loc_db.set_location_offset(head, section_base)

    # Generate deobfuscated assembly code
    patches = asm_resolve_final(mdis.arch,
                                asmcfg,
                                dst_interval=interval([
                                    (section_base,
                                     section_base + unmut_section.virtual_size)
                                ]))

    # Overwrite the section's content
    new_section_size = max(map(lambda a: a - section_base,
                               patches.keys())) + 15
    new_content = bytearray([0] * new_section_size)
    for addr, data in patches.items():
        offset = addr - section_base
        new_content[offset:offset + len(data)] = data
    # TODO: patch original location to jmp to the newly generated code
    unmut_section.content = memoryview(new_content)

    # Invoke the builder
    builder = lief.PE.Builder(pe_obj)
    builder.build()
    # Save the result
    builder.write(args.output)


def strip_sym_flags(symex: SymbolicExecutionEngine) -> None:
    symex.apply_change(m2_expr.ExprId("zf", 1), m2_expr.ExprId("zf", 1))
    symex.apply_change(m2_expr.ExprId("nf", 1), m2_expr.ExprId("nf", 1))
    symex.apply_change(m2_expr.ExprId("pf", 1), m2_expr.ExprId("pf", 1))
    symex.apply_change(m2_expr.ExprId("cf", 1), m2_expr.ExprId("cf", 1))
    symex.apply_change(m2_expr.ExprId("of", 1), m2_expr.ExprId("of", 1))
    symex.apply_change(m2_expr.ExprId("af", 1), m2_expr.ExprId("af", 1))


def handle_mov(
    mdis: disasmEngine,
    dst: m2_expr.Expr,
    value: Union[m2_expr.ExprId, m2_expr.ExprMem, m2_expr.ExprInt,
                 m2_expr.ExprSlice],
    zero_extended: bool = False,
) -> Optional[instruction]:
    if zero_extended:
        # Note(ergrelet): in x86, MOVZX only takes r/m8 and r/m16 operands
        if value.size <= 16:
            original_instr_str = f"MOVZX {ir_to_asm_str(dst)}, {ir_to_asm_str(value)}"
        else:
            # For other sizes, we simply use MOV and use a subregister as the destination
            if value.is_slice() and value.start == 0:
                dst = m2_expr.ExprSlice(dst, value.start, value.stop)
            original_instr_str = f"MOV {ir_to_asm_str(dst)}, {ir_to_asm_str(value)}"
    else:
        original_instr_str = f"MOV {ir_to_asm_str(dst)}, {ir_to_asm_str(value)}"
    original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db,
                                          mdis.attrib)
    print(original_instr)
    return original_instr


def handle_nary_op(mdis: disasmEngine, dst: m2_expr.Expr,
                   op_expr: m2_expr.ExprOp) -> Optional[instruction]:
    match op_expr.op:
    # ADD, SUB, INC, DEC, NEG (we treat this separately from other binary operations)
    # Note(ergrelet): SUB is lifted as ADD(VAL1, -VAL2), NEG is lifted as ADD(0, -VAL)
        case "+":
            return handle_add_operation(mdis, dst, op_expr)
        # AND, OR, XOR, NOT, SAR, SHR, SHL, ROR, ROL
        # Note(ergrelet): NOT is lifted as XOR(VAL, -1)
        case "&" | "|" | "^" | "a>>" | ">>" | "<<" | ">>>" | "<<<":
            return handle_binary_operation(mdis, dst, op_expr)
        case _:
            return None


def handle_compose(mdis: disasmEngine, dst: m2_expr.Expr,
                   compose_expr: m2_expr.ExprCompose) -> Optional[instruction]:
    inner_value_expr = compose_expr.args[0]

    # Match exprs of the form: '{RAX[0:32] + 0x1 0 32, 0x0 32 64}' (zero extension)
    is_zero_extension = len(compose_expr.args) == 2 and \
        compose_expr.args[1].is_int() and compose_expr.args[1].arg == 0
    # Match exprs of the form: '{RDX[0:8] + 0x1 0 8, RDX[8:64] 8 64}' (subregister)
    is_subregister = len(compose_expr.args) == 2 and \
        compose_expr.args[1].is_slice() and \
        compose_expr.args[1].arg.is_id() and dst == compose_expr.args[1].arg

    if is_zero_extension or is_subregister:
        match type(inner_value_expr):
            case m2_expr.ExprSlice:
                return handle_mov(mdis, dst, inner_value_expr,
                                  is_zero_extension)
            case m2_expr.ExprOp:
                return handle_nary_op(mdis, dst, inner_value_expr)

    return None


def handle_add_operation(mdis: disasmEngine, dst: m2_expr.Expr,
                         op_expr: m2_expr.ExprOp) -> Optional[instruction]:
    lhs = op_expr.args[0]
    rhs = op_expr.args[1]

    # Sub
    if rhs.is_op() and rhs.op == "-":
        if len(rhs.args) == 1 and not rhs.args[0].is_op():
            # DST = DST + (-RHS)
            if dst == lhs:
                original_instr_str = f"SUB {ir_to_asm_str(dst)}, {ir_to_asm_str(rhs.args[0])}"
                original_instr = mdis.arch.fromstring(original_instr_str,
                                                      mdis.loc_db, mdis.attrib)
                print(original_instr)
                return original_instr
            # DST = DST[0:XX] + (-RHS)
            elif is_a_slice_of(lhs, dst):
                dst = m2_expr.ExprSlice(dst, lhs.start, lhs.stop)
                original_instr_str = f"SUB {ir_to_asm_str(dst)}, {ir_to_asm_str(rhs.arg[0])}"
                original_instr = mdis.arch.fromstring(original_instr_str,
                                                      mdis.loc_db, mdis.attrib)
                print(original_instr)
                return original_instr

    # Sub
    if lhs.is_op() and lhs.op == "-":
        if len(lhs.args) == 1 and not lhs.args[0].is_op():
            # DST = (-LHS) + DST
            if dst == rhs:
                original_instr_str = f"SUB {ir_to_asm_str(dst)}, {ir_to_asm_str(lhs.arg[0])}"
                original_instr = mdis.arch.fromstring(original_instr_str,
                                                      mdis.loc_db, mdis.attrib)
                print(original_instr)
                return original_instr
            # DST = (-LHS) + DST[0:XX]
            elif is_a_slice_of(rhs, dst):
                dst = m2_expr.ExprSlice(dst, rhs.start, rhs.stop)
                original_instr_str = f"SUB {ir_to_asm_str(dst)}, {ir_to_asm_str(lhs.arg[0])}"
                original_instr = mdis.arch.fromstring(original_instr_str,
                                                      mdis.loc_db, mdis.attrib)
                print(original_instr)
                return original_instr

    # TODO: handle NEG

    # Add (regular binary operations)
    return handle_binary_operation(mdis, dst, op_expr)


def handle_binary_operation(mdis: disasmEngine, dst: m2_expr.Expr,
                            op_expr: m2_expr.ExprOp) -> Optional[instruction]:
    op_asm_str = X86_BINARY_OPS_MAPPING.get(op_expr.op)
    if op_asm_str is None:
        # Unsupported operation
        return None

    lhs = op_expr.args[0]
    rhs = op_expr.args[1]
    if not lhs.is_op() and not rhs.is_op():
        # DST = OP(DST, RHS)
        if dst == lhs:
            original_instr_str = f"{op_asm_str} {ir_to_asm_str(dst)}, {ir_to_asm_str(rhs)}"
            original_instr = mdis.arch.fromstring(original_instr_str,
                                                  mdis.loc_db, mdis.attrib)
            print(original_instr)
            return original_instr
        # DST = OP(LHS, DST)
        elif dst == rhs:
            original_instr_str = f"{op_asm_str} {ir_to_asm_str(dst)}, {ir_to_asm_str(lhs)}"
            original_instr = mdis.arch.fromstring(original_instr_str,
                                                  mdis.loc_db, mdis.attrib)
            print(original_instr)
            return original_instr
        # DST = OP(DST[0:XX], RHS)
        elif is_a_slice_of(lhs, dst):
            dst = m2_expr.ExprSlice(dst, lhs.start, lhs.stop)
            original_instr_str = f"{op_asm_str} {ir_to_asm_str(dst)}, {ir_to_asm_str(rhs)}"
            original_instr = mdis.arch.fromstring(original_instr_str,
                                                  mdis.loc_db, mdis.attrib)
            print(original_instr)
            return original_instr
        # DST = OP(LHS, DST[0:XX])
        elif is_a_slice_of(rhs, dst):
            dst = m2_expr.ExprSlice(dst, rhs.start, rhs.stop)
            original_instr_str = f"{op_asm_str} {ir_to_asm_str(dst)}, {ir_to_asm_str(lhs)}"
            original_instr = mdis.arch.fromstring(original_instr_str,
                                                  mdis.loc_db, mdis.attrib)
            print(original_instr)
            return original_instr

    return None


def handle_xchg(
        mdis: disasmEngine, assignblk1: Tuple[m2_expr.Expr, m2_expr.Expr],
        assignblk2: Tuple[m2_expr.Expr,
                          m2_expr.Expr]) -> Optional[instruction]:
    if assignblk1[0] == assignblk2[1] and \
            assignblk2[0] == assignblk1[1]:
        print(assignblk1)
        print(assignblk2)

        original_instr_str = f"XCHG {ir_to_asm_str(assignblk1[0])}, {ir_to_asm_str(assignblk2[1])}?"
        original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db,
                                              mdis.attrib)
        print(original_instr)
        return original_instr

    return None


def handle_push(
        mdis: disasmEngine, assignblk1: Tuple[m2_expr.Expr, m2_expr.Expr],
        assignblk2: Tuple[m2_expr.Expr,
                          m2_expr.Expr]) -> Optional[instruction]:
    rsp_decrement_op = m2_expr.ExprOp("+", m2_expr.ExprId("RSP", 64),
                                      m2_expr.ExprInt(0xFFFFFFFFFFFFFFF8, 64))
    is_rsp_decremented = assignblk1[1] == rsp_decrement_op
    is_dst1_rsp = assignblk1[0].is_id() and assignblk1[0].name == "RSP"
    is_dst2_on_stack = assignblk2[0].is_mem() and \
        assignblk2[0].ptr == rsp_decrement_op

    if is_dst1_rsp and is_rsp_decremented and is_dst2_on_stack:
        original_instr_str = f"PUSH {ir_to_asm_str(assignblk2[1])}"
        original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db,
                                              mdis.attrib)
        print(original_instr)
        return original_instr

    return None


def handle_pop(
        mdis: disasmEngine, assignblk1: Tuple[m2_expr.Expr, m2_expr.Expr],
        assignblk2: Tuple[m2_expr.Expr,
                          m2_expr.Expr]) -> Optional[instruction]:
    rsp_increment_op = m2_expr.ExprOp("+", m2_expr.ExprId("RSP", 64),
                                      m2_expr.ExprInt(0x8, 64))
    is_rsp_incremented = assignblk2[1] == rsp_increment_op
    is_value1_on_stack = assignblk1[1].is_mem() and assignblk1[1].ptr.is_id() \
            and assignblk1[1].ptr.name == "RSP"
    is_dst2_rsp = assignblk2[0].is_id() and assignblk2[0].name == "RSP"

    if is_value1_on_stack and is_rsp_incremented and is_dst2_rsp:
        original_instr_str = f"POP {ir_to_asm_str(assignblk1[0])}"
        original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db,
                                              mdis.attrib)
        print(original_instr)
        return original_instr

    return None


def ir_to_asm_str(expr: m2_expr.Expr) -> str:
    match type(expr):
        case m2_expr.ExprMem:
            return mem_ir_to_asm_str(expr)
        case m2_expr.ExprSlice:
            return slice_ir_to_asm_str(expr)
        case _:
            return str(expr)


def mem_ir_to_asm_str(mem_expr: m2_expr.ExprMem) -> str:
    match mem_expr.size:
        case 64:
            return f"QWORD PTR [{mem_expr.ptr}]"
        case 32:
            return f"DWORD PTR [{mem_expr.ptr}]"
        case 16:
            return f"WORD PTR [{mem_expr.ptr}]"
        case 8:
            return f"BYTE PTR [{mem_expr.ptr}]"
        case _:
            raise Exception("Invalid ExprMem size")


def slice_ir_to_asm_str(slice_expr: m2_expr.ExprSlice) -> str:
    match type(slice_expr.arg):
        case m2_expr.ExprId:
            # Slice of a register
            return AMD64_SLICES_MAPPING[str(slice_expr)]
        case _:
            return str(expr)


def is_a_slice_of(slice_expr: m2_expr.Expr, expr: m2_expr.Expr) -> bool:
    return slice_expr.is_slice() and slice_expr.arg == expr


# Fix RIP relative instructions to make them relocatable
def fix_rip_relative_instruction(asmcfg: AsmCFG,
                                 instr: instruction) -> instruction:
    rip = m2_expr.ExprId("RIP", 64)
    # Note(ergrelet): see https://github.com/cea-sec/miasm/issues/1258#issuecomment-645640366
    # for more information on what the '_' symbol is used for.
    new_next_addr_card = m2_expr.ExprLoc(
        asmcfg.loc_db.get_or_create_name_location('_'), 64)
    for i in range(len(instr.args)):
        if rip in instr.args[i]:
            next_addr = m2_expr.ExprInt(instr.offset + instr.l, 64)
            fix_dict = {rip: rip + next_addr - new_next_addr_card}
            instr.args[i] = instr.args[i].replace_expr(fix_dict)

    return instr


if __name__ == "__main__":
    main()
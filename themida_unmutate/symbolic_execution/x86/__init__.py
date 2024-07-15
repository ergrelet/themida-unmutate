import itertools
from typing import Optional, Union

import miasm.arch.x86.arch as x86_arch
import miasm.expression.expression as m2_expr
from miasm.core.asmblock import AsmCFG, disasmEngine
from miasm.core.cpu import instruction
from miasm.core.interval import interval
from miasm.ir.symbexec import SymbolicExecutionEngine

from themida_unmutate.logging import logger
from themida_unmutate.miasm_utils import MiasmContext, MiasmFunctionInterval, expr_int_to_int

AMD64_PTR_SIZE = 64
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
AMD64_SLICES_MAPPING = {v: k for k, v in x86_arch.replace_regs64.items()}
AMD64_SP_REG = "RSP"
AMD64_IP_REG = "RIP"

MiasmIRAssignment = tuple[m2_expr.Expr, m2_expr.Expr]


def disassemble_and_simplify_functions(
        miasm_ctx: MiasmContext, mutated_func_addrs: list[int]) -> list[tuple[int, AsmCFG, MiasmFunctionInterval]]:
    """
    Disassemble mutated functions, simplify their `AsmCFG` and return them.
    """
    # Iterate through functions, disassemble and simplify them
    simplified_func_asmcfgs: list[tuple[int, AsmCFG, MiasmFunctionInterval]] = []
    for mutated_code_addr in mutated_func_addrs:
        logger.info("Simplifying function at 0x%x..." % mutated_code_addr)

        # Disassemble function
        asm_cfg = miasm_ctx.mdis.dis_multiblock(mutated_code_addr)
        # Compute function's interval (this is needed when rewriting the binary
        # in-place)
        original_func_interval: MiasmFunctionInterval = interval(blk.get_range() for blk in asm_cfg.blocks)

        # Lift assembly to IR
        ir_cfg = miasm_ctx.lifter.new_ircfg_from_asmcfg(asm_cfg)

        # Process IR basic blocks
        for loc_key, ir_block in ir_cfg.blocks.items():
            logger.debug("%s:" % str(loc_key))
            asm_block = asm_cfg.loc_key_to_block(loc_key)
            if asm_block is None:
                # Some instructions such `idiv` generate multiple IR basic blocks from a single asm instruction, so we
                # skip these
                continue

            relevant_assignblks = ir_block.assignblks[:-1]
            relevant_blk_count = len(relevant_assignblks)
            # No relevant instruction
            # -> unmutated, branching instruction -> keep as is
            if relevant_blk_count == 0:
                logger.debug(ir_block.assignblks[0].instr)
                continue

            # Only 1 or 2 relevant instructions
            # -> unmutated, no junk code -> no action needed -> keep first instruction as is
            if relevant_blk_count <= 2:
                logger.debug(ir_block.assignblks[0].instr)
                relocatable_instr = fix_rip_relative_instruction(asm_cfg, ir_block.assignblks[0].instr)
                asm_block.lines[0] = relocatable_instr
                continue

            reference_sb = SymbolicExecutionEngine(miasm_ctx.lifter)
            for assign_block in relevant_assignblks:
                reference_sb.eval_updt_assignblk(assign_block)
                # Forget dead stack slots
                reference_sb.del_mem_above_stack(miasm_ctx.lifter.sp)

            # Strip FLAGS register (as these are trashed by the mutation)
            strip_sym_flags(reference_sb)

            # More than 2 instructions but a single instruction replicates the symbolic state
            #   -> unmutated, junk code inserted -> keep the one instruction as is
            block_simplified = False
            for assignblk_subset in itertools.combinations(relevant_assignblks, 1):
                sb = SymbolicExecutionEngine(miasm_ctx.lifter)

                for assign_block in assignblk_subset:
                    sb.eval_updt_assignblk(assign_block)
                reference_sb.del_mem_above_stack(miasm_ctx.lifter.sp)

                # Check if instruction replicates the symbolic state
                if reference_sb.get_state() == sb.get_state():
                    for a in assignblk_subset:
                        logger.debug(a.instr)
                        # Update block asm block
                        relocatable_instr = fix_rip_relative_instruction(asm_cfg, a.instr)
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
                    logger.debug(asm_block.lines[-1])
                    asm_block.lines = [asm_block.lines[-1]]
                    continue

                # 1 assignment block: MOV, XCHG, n-ary operators
                case 1:
                    ir_assignment = next(iter(modified_variables.items()))
                    dst, value = normalize_ir_assigment(ir_assignment)
                    match type(value):
                        case m2_expr.ExprId | m2_expr.ExprMem | m2_expr.ExprInt | m2_expr.ExprSlice:
                            # Assignation
                            # -> MOV
                            match type(dst):
                                case m2_expr.ExprId | m2_expr.ExprMem | m2_expr.ExprSlice:
                                    original_instr = handle_mov(miasm_ctx.mdis, dst, value)
                                    if original_instr is not None:
                                        # Update block asm block
                                        relocatable_instr = fix_rip_relative_instruction(asm_cfg, original_instr)
                                        asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                                        continue

                        case m2_expr.ExprOp:
                            # N-ary operation on native-size registers
                            # -> ADD/SUB/INC/DEC/AND/OR/XOR/NEG/NOT/ROL/ROR/SAR/SHL/SHR
                            original_instr = handle_nary_op(miasm_ctx.mdis, dst, value)
                            if original_instr is not None:
                                # Update block asm block
                                relocatable_instr = fix_rip_relative_instruction(asm_cfg, original_instr)
                                asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                                continue

                        case m2_expr.ExprCompose:
                            # MOV, XCHG on single register or n-ary operation on lower-sized registers
                            original_instr = handle_compose(miasm_ctx.mdis, dst, value)
                            if original_instr is not None:
                                # Update block asm block
                                relocatable_instr = fix_rip_relative_instruction(asm_cfg, original_instr)
                                asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                                continue

                # 2 assignment blocks
                # -> PUSH, POP, XCHG, `SUB RSP, X`
                case 2:
                    modified_variables_iter = iter(modified_variables.items())
                    assignblk1 = next(modified_variables_iter)
                    assignblk2 = next(modified_variables_iter)

                    # PUSH
                    original_instr = handle_push(miasm_ctx.mdis, assignblk1, assignblk2)
                    if original_instr is not None:
                        # Update block asm block
                        relocatable_instr = fix_rip_relative_instruction(asm_cfg, original_instr)
                        asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                        continue
                    # POP
                    original_instr = handle_pop(miasm_ctx.mdis, assignblk1, assignblk2)
                    if original_instr is not None:
                        # Update block asm block
                        relocatable_instr = fix_rip_relative_instruction(asm_cfg, original_instr)
                        asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                        continue
                    # XCHG
                    original_instr = handle_xchg(miasm_ctx.mdis, assignblk1, assignblk2)
                    if original_instr is not None:
                        # Update block asm block
                        relocatable_instr = fix_rip_relative_instruction(asm_cfg, original_instr)
                        asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                        continue

                    # `SUB RSP, X`
                    original_instr = handle_sub_rsp(miasm_ctx.mdis, modified_variables)
                    if original_instr is not None:
                        # Update block asm block
                        relocatable_instr = fix_rip_relative_instruction(asm_cfg, original_instr)
                        asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                        continue

                # More than 2 assignment blocks
                # -> `SUB RSP, X`
                case _:
                    original_instr = handle_sub_rsp(miasm_ctx.mdis, modified_variables)
                    if original_instr is not None:
                        # Update block asm block
                        relocatable_instr = fix_rip_relative_instruction(asm_cfg, original_instr)
                        asm_block.lines = [relocatable_instr, asm_block.lines[-1]]
                        continue

            logger.debug(modified_variables)
            logger.warning("Unsupported instruction or unmutated block found. "
                           "Block will be kept as is.")

        simplified_func_asmcfgs.append((mutated_code_addr, asm_cfg, original_func_interval))

    return simplified_func_asmcfgs


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
    value: Union[m2_expr.ExprId, m2_expr.ExprMem, m2_expr.ExprInt, m2_expr.ExprSlice],
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
    original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
    logger.debug(original_instr)
    return original_instr


def handle_nary_op(mdis: disasmEngine, dst: m2_expr.Expr, op_expr: m2_expr.ExprOp) -> Optional[instruction]:
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


def handle_compose(mdis: disasmEngine, dst: m2_expr.Expr, compose_expr: m2_expr.ExprCompose) -> Optional[instruction]:
    inner_value_expr = compose_expr.args[0]

    # Match exprs of the form: '{RAX[0:32] + 0x1 0 32, 0x0 32 64}' (zero extension)
    is_zero_extension = len(compose_expr.args) == 2 and \
        compose_expr.args[1].is_int() and compose_expr.args[1].arg == 0
    # Match exprs of the form: '{RDX[0:8] + 0x1 0 8, RDX[8:64] 8 64}' (subregister)
    is_subregister_assign = len(compose_expr.args) == 2 and \
        compose_expr.args[1].is_slice() and \
        compose_expr.args[1].arg.is_id() and dst == compose_expr.args[1].arg
    if is_zero_extension or is_subregister_assign:
        match type(inner_value_expr):
            case m2_expr.ExprSlice:
                return handle_mov(mdis, dst, inner_value_expr, is_zero_extension)
            case m2_expr.ExprOp:
                return handle_nary_op(mdis, dst, inner_value_expr)

    # Handle XCHG cases where DST and SRC are subregisters of the same register
    # Match exprs of the form: '{RCX[8:16] 0 8, RCX[0:8] 8 16, RCX[16:64] 16 64}' (subregister swap)
    is_subregister_swap = len(compose_expr.args) == 3 and \
        all(map(lambda expr: expr.is_slice() and expr.arg.is_id() and expr.arg == dst,
                compose_expr.args))
    if is_subregister_swap:
        compose_lower_part, compose_mid_part, _ = compose_expr.args
        # 8-bit subregisters swap
        if compose_lower_part.size == compose_mid_part.size == 8:
            return handle_xchg(mdis, (compose_lower_part, compose_mid_part), (compose_mid_part, compose_lower_part))

    return None


def handle_add_operation(mdis: disasmEngine, dst: m2_expr.Expr, op_expr: m2_expr.ExprOp) -> Optional[instruction]:
    lhs = op_expr.args[0]
    rhs = op_expr.args[1]

    # Sub
    if rhs.is_op() and rhs.op == "-":
        if len(rhs.args) == 1 and not rhs.args[0].is_op():
            # DST = DST + (-RHS)
            if dst == lhs:
                original_instr_str = f"SUB {ir_to_asm_str(dst)}, {ir_to_asm_str(rhs.args[0])}"
                original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
                logger.debug(original_instr)
                return original_instr
            # DST = DST[0:XX] + (-RHS)
            if is_a_slice_of(lhs, dst):
                dst = m2_expr.ExprSlice(dst, lhs.start, lhs.stop)
                original_instr_str = f"SUB {ir_to_asm_str(dst)}, {ir_to_asm_str(rhs.args[0])}"
                original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
                logger.debug(original_instr)
                return original_instr

    # Sub
    if lhs.is_op() and lhs.op == "-":
        if len(lhs.args) == 1 and not lhs.args[0].is_op():
            # DST = (-LHS) + DST
            if dst == rhs:
                original_instr_str = f"SUB {ir_to_asm_str(dst)}, {ir_to_asm_str(lhs.args[0])}"
                original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
                logger.debug(original_instr)
                return original_instr
            # DST = (-LHS) + DST[0:XX]
            if is_a_slice_of(rhs, dst):
                dst = m2_expr.ExprSlice(dst, rhs.start, rhs.stop)
                original_instr_str = f"SUB {ir_to_asm_str(dst)}, {ir_to_asm_str(lhs.args[0])}"
                original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
                logger.debug(original_instr)
                return original_instr

    # TODO: handle NEG?

    # Add (regular binary operations)
    return handle_binary_operation(mdis, dst, op_expr)


def handle_binary_operation(mdis: disasmEngine, dst: m2_expr.Expr, op_expr: m2_expr.ExprOp) -> Optional[instruction]:
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
            original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
            logger.debug(original_instr)
            return original_instr
        # DST = OP(LHS, DST)
        if dst == rhs:
            original_instr_str = f"{op_asm_str} {ir_to_asm_str(dst)}, {ir_to_asm_str(lhs)}"
            original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
            logger.debug(original_instr)
            return original_instr
        # DST = OP(DST[0:XX], RHS)
        if is_a_slice_of(lhs, dst):
            dst = m2_expr.ExprSlice(dst, lhs.start, lhs.stop)
            original_instr_str = f"{op_asm_str} {ir_to_asm_str(dst)}, {ir_to_asm_str(rhs)}"
            original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
            logger.debug(original_instr)
            return original_instr
        # DST = OP(LHS, DST[0:XX])
        if is_a_slice_of(rhs, dst):
            dst = m2_expr.ExprSlice(dst, rhs.start, rhs.stop)
            original_instr_str = f"{op_asm_str} {ir_to_asm_str(dst)}, {ir_to_asm_str(lhs)}"
            original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
            logger.debug(original_instr)
            return original_instr

    return None


def handle_xchg(mdis: disasmEngine, ir_assignment1: MiasmIRAssignment,
                ir_assignment2: MiasmIRAssignment) -> Optional[instruction]:
    norm_assignment1 = normalize_ir_assigment(ir_assignment1)
    norm_assignment2 = normalize_ir_assigment(ir_assignment2)

    # Handle most XCHG cases where DST and SRC are swapped and aren't part of
    # the same register
    if norm_assignment1[0] == norm_assignment2[1] and \
            norm_assignment2[0] == norm_assignment1[1]:
        original_instr_str = f"XCHG {ir_to_asm_str(norm_assignment2[0])}, {ir_to_asm_str(norm_assignment2[1])}"
        original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
        logger.debug(original_instr)
        return original_instr

    return None


def handle_push(mdis: disasmEngine, ir_assignment1: MiasmIRAssignment,
                ir_assignment2: MiasmIRAssignment) -> Optional[instruction]:
    rsp_decrement_op = m2_expr.ExprOp("+", m2_expr.ExprId(AMD64_SP_REG, AMD64_PTR_SIZE),
                                      m2_expr.ExprInt(0xFFFFFFFFFFFFFFF8, AMD64_PTR_SIZE))
    is_rsp_decremented = ir_assignment1[1] == rsp_decrement_op
    is_dst1_rsp = ir_assignment1[0].is_id() and ir_assignment1[0].name == AMD64_SP_REG
    is_dst2_on_stack = ir_assignment2[0].is_mem() and \
                       ir_assignment2[0].ptr == rsp_decrement_op

    if is_dst1_rsp and is_rsp_decremented and is_dst2_on_stack:
        original_instr_str = f"PUSH {ir_to_asm_str(ir_assignment2[1])}"
        original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
        logger.debug(original_instr)
        return original_instr

    return None


def handle_pop(mdis: disasmEngine, ir_assignment1: MiasmIRAssignment,
               ir_assignment2: MiasmIRAssignment) -> Optional[instruction]:
    rsp_increment_op = m2_expr.ExprOp("+", m2_expr.ExprId(AMD64_SP_REG, AMD64_PTR_SIZE),
                                      m2_expr.ExprInt(0x8, AMD64_PTR_SIZE))
    is_rsp_incremented = ir_assignment2[1] == rsp_increment_op
    is_value1_on_stack = ir_assignment1[1].is_mem() and \
                         ir_assignment1[1].ptr.is_id() and ir_assignment1[1].ptr.name == AMD64_SP_REG
    is_dst2_rsp = ir_assignment2[0].is_id() and \
                  ir_assignment2[0].name == AMD64_SP_REG

    if is_value1_on_stack and is_rsp_incremented and is_dst2_rsp:
        original_instr_str = f"POP {ir_to_asm_str(ir_assignment1[0])}"
        original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
        logger.debug(original_instr)
        return original_instr

    return None


# Note(ergrelet): `SUB RSP, X` is a special case where there might be some residual
# constraints that the symbolic execution cannot discard, because allocated stack
# slots are live and values might have been assigned to some of them by the
# inserted junk code.
# We thus have to differentiate legit PUSH-like instructions from junked
# `SUB RSP, X` instructions.
def handle_sub_rsp(mdis: disasmEngine, assign_blk: dict[m2_expr.Expr, m2_expr.Expr]) -> Optional[instruction]:

    def is_sub_rsp_expr(expr: m2_expr.Expr) -> bool:
        """
        This matches OP expressions of the form "RSP - X"
        """
        if not expr.is_op():
            return False

        is_binary_add = expr.op == "+" and len(expr.args) == 2
        if not is_binary_add:
            return False

        # One of the operands must be RSP
        rsp_in_expr = any(map(lambda arg: arg.is_id() and arg.name == AMD64_SP_REG, expr.args))
        # The other operand must be a negative integer
        neg_int_in_expr = any(map(lambda arg: arg.is_int() and expr_int_to_int(arg) < 0, expr.args))

        return rsp_in_expr and neg_int_in_expr

    def is_sub_rsp_blk(ir_assignment: MiasmIRAssignment) -> bool:
        """
        This matches assignments of the form "RSP - X"
        """
        dst, src = ir_assignment
        if not dst.is_id() or not src.is_op():
            return False

        # Destination must be RSP
        dst_is_rsp = dst.name == AMD64_SP_REG
        return dst_is_rsp and is_sub_rsp_expr(src)

    # Check if a SUB operation is applied to RSP
    sub_rsp_blk = next(filter(is_sub_rsp_blk, assign_blk.items()), None)
    if sub_rsp_blk is not None:
        # Extract allocated size
        allocated_window = (0, expr_int_to_int(sub_rsp_blk[1].args[1]))
        # Check if all allocated slots have been written to or not. This
        # assumes no PUSH-like x86 instruction allocates more slots than needed to
        # write the data it pushes to the stack
        #
        # FIXME: we're not checking individual stack slots but rather
        # the outter boundaries from used stack slots. It would be better
        # to track accesses to each stack slot separately.
        used_window = [0, 0]
        for dst in assign_blk.keys():
            if dst.is_mem() and is_sub_rsp_expr(dst.ptr):
                dst_offset_in_stack = expr_int_to_int(dst.ptr.args[1])
                dst_size_in_bytes = dst.size // 8
                used_window[0] = max(used_window[0], dst_offset_in_stack + dst_size_in_bytes)
                used_window[1] = min(used_window[1], dst_offset_in_stack)
        if tuple(used_window) == allocated_window:
            # All allocated slots are used, must be a PUSH-like instruction
            return None

        original_instr_str = f"SUB {AMD64_SP_REG}, {-allocated_window[1]}"
        original_instr = mdis.arch.fromstring(original_instr_str, mdis.loc_db, mdis.attrib)
        logger.debug(original_instr)
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
        case 128 | 64 | 32 | 16 | 8:
            mem_prefix = x86_arch.SIZE2MEMPREFIX[mem_expr.size]
            return f"{mem_prefix} PTR [{mem_expr.ptr}]"
        case _:
            raise ValueError("Invalid ExprMem size")


def slice_ir_to_asm_str(slice_expr: m2_expr.ExprSlice) -> str:
    match type(slice_expr.arg):
        case m2_expr.ExprId:
            # Slice of a register
            return str(AMD64_SLICES_MAPPING[slice_expr])
        case _:
            return str(slice_expr)


def normalize_ir_assigment(ir_assignment: MiasmIRAssignment) -> MiasmIRAssignment:
    """
    Normalize IR assignments by transforming `ExprCompose`s in SRC into
    `ExprSlice`s in DST when appropriate.
    This allows us to properly detect assigments made to subregisters
    (e.g., `EAX`, `AX`, `AL`, `AH`).
    """
    dst, src = ir_assignment

    # Match ExprId(X) = ExprCompose(Y)
    if dst.is_id() and src.is_compose():
        match len(src.args):
        # 2-way compose (e.g., `EAX`, `AX`, `AL`)
            case 2:
                compose_lower_part, compose_upper_part = src.args
                # If upper bits from DST are kept, it means we're dealing with
                # a 16-bit or 8-bit subregister
                if compose_upper_part.arg == dst and \
                        compose_upper_part.start == compose_lower_part.size and \
                        compose_upper_part.stop == dst.size:
                    # DST -> DST[0:X]
                    new_dst = m2_expr.ExprSlice(dst, 0, compose_lower_part.size)
                    # Concat(SRC[0:X], DST[X:]) -> SRC[0:X]
                    new_src = compose_lower_part
                    return (new_dst, new_src)

                # If upper bits are zeroed out, it means mean we're dealing with
                # a 32-bit subregister
                upper_zero_bits = m2_expr.ExprInt(0, AMD64_PTR_SIZE // 2)
                if compose_upper_part == upper_zero_bits:
                    # DST -> DST[0:32]
                    new_dst = m2_expr.ExprSlice(dst, 0, compose_lower_part.size)
                    # Concat(SRC, DST[X:]) -> SRC
                    new_src = compose_lower_part

                    return (new_dst, new_src)

            # 3-way compose (e.g., `AH`, `BH`)
            case 3:
                compose_lower_part, compose_mid_part, compose_upper_part = src.args
                # If lower and upper bits from DST are kept, it means we're
                # dealing with a subregister
                if compose_lower_part.arg == dst and \
                        compose_lower_part.start == 0 and \
                        compose_upper_part.arg == dst and \
                        compose_upper_part.stop == dst.size:
                    # DST -> DST[X:Y]
                    new_dst = m2_expr.ExprSlice(dst, compose_lower_part.size,
                                                compose_lower_part.size + compose_mid_part.size)
                    # Concat(DST[0:X], SRC, DST[Y:]) -> SRC
                    new_src = compose_mid_part
                    return (new_dst, new_src)

    return ir_assignment


def is_a_slice_of(slice_expr: m2_expr.Expr, expr: m2_expr.Expr) -> bool:
    return slice_expr.is_slice() and slice_expr.arg == expr  # type:ignore


# Fix RIP relative instructions to make them relocatable
def fix_rip_relative_instruction(asmcfg: AsmCFG, instr: instruction) -> instruction:
    rip = m2_expr.ExprId(AMD64_IP_REG, AMD64_PTR_SIZE)
    # Note(ergrelet): see https://github.com/cea-sec/miasm/issues/1258#issuecomment-645640366
    # for more information on what the '_' symbol is used for.
    new_next_addr_card = m2_expr.ExprLoc(asmcfg.loc_db.get_or_create_name_location('_'), AMD64_PTR_SIZE)
    for i, arg in enumerate(instr.args):
        if rip in arg:
            assert instr.offset is not None and instr.l is not None
            next_instr_addr = m2_expr.ExprInt(instr.offset + instr.l, AMD64_PTR_SIZE)
            fix_dict = {rip: rip + next_instr_addr - new_next_addr_card}
            instr.args[i] = arg.replace_expr(fix_dict)

    # Note(ergrelet): reset the instruction's additional info to avoid
    # certain assembling issues where instruction prefixes are mixed
    # in an illegal way.
    reset_additional_instruction_info(instr)

    return instr


def reset_additional_instruction_info(instr: instruction) -> None:
    instr.additional_info = x86_arch.additional_info()
    instr.additional_info.g1.value = 0
    instr.additional_info.g2.value = 0
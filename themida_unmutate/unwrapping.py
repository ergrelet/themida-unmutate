import miasm.expression.expression as m2_expr
from miasm.ir.ir import IRCFG, Lifter
from miasm.ir.symbexec import SymbolicExecutionEngine

from themida_unmutate.logging import logger
from themida_unmutate.miasm_utils import MiasmContext, expr_int_to_int


def unwrap_functions(miasm_ctx: MiasmContext, target_function_addrs: list[int]) -> list[int]:
    """
    Resolve mutated function's addresses from original function addresses.
    """
    mutated_func_addrs: list[int] = []
    for addr in target_function_addrs:
        logger.debug("Resolving mutated code portion address for 0x%x..." % addr)
        mutated_code_addr = _resolve_mutated_code_address(miasm_ctx, addr)
        if mutated_code_addr == addr:
            raise Exception("Failure to unwrap function")

        logger.info("Function at 0x%x jumps to 0x%x" % (addr, mutated_code_addr))
        mutated_func_addrs.append(mutated_code_addr)

    return mutated_func_addrs


def _resolve_mutated_code_address(miasm_ctx: MiasmContext, target_addr: int) -> int:
    # Save `follow_call` value and set it to `True`
    saved_follow_call = miasm_ctx.mdis.follow_call
    miasm_ctx.mdis.follow_call = True
    # Disassemble trampoline
    asmcfg = miasm_ctx.mdis.dis_multiblock(target_addr)
    # Restore `follow_call` value
    miasm_ctx.mdis.follow_call = saved_follow_call
    # Lift ASM to IR
    ircfg = miasm_ctx.lifter.new_ircfg_from_asmcfg(asmcfg)

    return _resolve_mutated_portion_address(miasm_ctx.lifter, ircfg, target_addr)


def _resolve_mutated_portion_address(lifter: Lifter, ircfg: IRCFG, call_addr: int) -> int:
    # Instantiate a Symbolic Execution engine with default value for registers
    symb = SymbolicExecutionEngine(lifter)

    # Emulate until the next address cannot be resolved (`ret`, unresolved condition, etc.)
    cur_expr = symb.run_at(ircfg, call_addr)

    # First `cmp` -> eval to zero
    if not cur_expr.is_cond() or not cur_expr.cond.is_mem():
        logger.warning("Function doesn't behave as expected, considering it unmutated")
        return call_addr

    # Value if condition is evaled zero
    symb.eval_updt_expr(m2_expr.ExprAssign(cur_expr.cond, m2_expr.ExprInt(0, cur_expr.cond.size)))
    target = cur_expr.src2
    cur_expr = symb.run_at(ircfg, target)

    # Second `cmp` -> eval to zero
    if not cur_expr.is_cond() or not cur_expr.cond.is_mem():
        logger.warning("Function doesn't behave as expected, considering it unmutated")
        return call_addr

    # Value if condition is evaled zero
    symb.eval_updt_expr(m2_expr.ExprAssign(cur_expr.cond, m2_expr.ExprInt(0, cur_expr.cond.size)))
    target = cur_expr.src2
    cur_expr = symb.run_at(ircfg, target)
    if not isinstance(cur_expr, m2_expr.ExprInt):
        # If we're here, this might be a Themida 3.1.7+ trampoline, handle the additional JCC
        if not cur_expr.is_cond() or not cur_expr.cond.is_mem():
            logger.warning("Function doesn't behave as expected, considering it unmutated")
            return call_addr

        symb.eval_updt_expr(m2_expr.ExprAssign(cur_expr.cond, m2_expr.ExprInt(0, cur_expr.cond.size)))
        target = cur_expr.src2
        cur_expr = symb.run_at(ircfg, target)
        if not isinstance(cur_expr, m2_expr.ExprInt):
            logger.warning("Function doesn't behave as expected, considering it unmutated")
            return call_addr

    # This time we should have the real mutated function address
    return expr_int_to_int(cur_expr)

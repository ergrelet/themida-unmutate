import miasm.expression.expression as m2_expr
from miasm.ir.ir import IRCFG, Lifter
from miasm.ir.symbexec import SymbolicExecutionEngine

from themida_unmutate.miasm_utils import MiasmContext, expr_int_to_int


def unwrap_function(target_bin_path: str, target_addr: int) -> int:
    # Setup disassembler and lifter
    miasm_ctx = MiasmContext(target_bin_path)

    # Disassemble trampoline
    miasm_ctx.mdis.follow_call = True
    asmcfg = miasm_ctx.mdis.dis_multiblock(target_addr)

    # Lift ASM to IR
    ircfg = miasm_ctx.lifter.new_ircfg_from_asmcfg(asmcfg)

    return _resolve_mutated_portion_address(miasm_ctx.lifter, ircfg,
                                            target_addr)


def _resolve_mutated_portion_address(lifter: Lifter, ircfg: IRCFG,
                                     call_addr: int) -> int:
    # Instantiate a Symbolic Execution engine with default value for registers
    symb = SymbolicExecutionEngine(lifter)

    # Emulate until the next address cannot be resolved (`ret`, unresolved condition, etc.)
    cur_expr = symb.run_at(ircfg, call_addr)

    # First `cmp` -> eval to zero
    if not cur_expr.is_cond() or not cur_expr.cond.is_mem():
        print("Function doesn't behave as expected, considering it unmutated")
        return call_addr

    # Value if condition is evaled zero
    symb.eval_updt_expr(
        m2_expr.ExprAssign(cur_expr.cond,
                           m2_expr.ExprInt(0, cur_expr.cond.size)))
    target = cur_expr.src2
    cur_expr = symb.run_at(ircfg, target)

    # Second `cmp` -> eval to zero
    if not cur_expr.is_cond() or not cur_expr.cond.is_mem():
        print("Function doesn't behave as expected, considering it unmutated")
        return call_addr

    # Value if condition is evaled zero
    symb.eval_updt_expr(
        m2_expr.ExprAssign(cur_expr.cond,
                           m2_expr.ExprInt(0, cur_expr.cond.size)))
    target = cur_expr.src2
    cur_expr = symb.run_at(ircfg, target)
    assert isinstance(cur_expr, m2_expr.ExprInt)

    # This time we should have the real mutated function address
    return expr_int_to_int(cur_expr)

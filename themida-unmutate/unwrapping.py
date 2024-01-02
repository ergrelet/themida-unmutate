import miasm.expression.expression as m2_expr
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.ir.ir import IRCFG, Lifter
from miasm.ir.symbexec import SymbolicExecutionEngine

from .miasm_utils import expr_int_to_int


def unwrap_function(target_bin: str, target_arch: str,
                    target_addr: int) -> int:
    loc_db = LocationDB()
    # This part focus on obtaining an IRCFG to transform
    cont = Container.from_stream(open(target_bin, 'rb'), loc_db)
    machine = Machine(target_arch if target_arch else cont.arch)
    lifter = machine.lifter(loc_db)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
    mdis.follow_call = True

    asmcfg = mdis.dis_multiblock(target_addr)
    # Lift asm to IR
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

    return _resolve_mutated_portion_address(lifter, ircfg, target_addr)


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

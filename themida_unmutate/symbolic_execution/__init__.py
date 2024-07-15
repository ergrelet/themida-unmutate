from miasm.core.asmblock import AsmCFG

import themida_unmutate.symbolic_execution.x86 as symex_x86
from themida_unmutate.miasm_utils import MiasmContext, MiasmFunctionInterval


def disassemble_and_simplify_functions(
        miasm_ctx: MiasmContext, mutated_func_addrs: list[int]) -> list[tuple[int, AsmCFG, MiasmFunctionInterval]]:
    """
    Disassemble mutated functions, simplify their `AsmCFG` and return them.
    """
    match miasm_ctx.arch:
        case "x86_64":
            return symex_x86.disassemble_and_simplify_functions(miasm_ctx, mutated_func_addrs)

        case _:
            raise NotImplementedError("Unsupported architecture")

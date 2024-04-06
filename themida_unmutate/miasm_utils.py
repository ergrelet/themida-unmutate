from dataclasses import dataclass

import miasm.expression.expression as m2_expr

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.asmblock import disasmEngine
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

    def __init__(self, target_binary_path: str) -> None:
        """
        Initialize our Miasm context, targeted at x86_64 binaries.
        """
        self.loc_db = LocationDB()
        with open(target_binary_path, 'rb') as target_binary:
            self.container = Container.from_stream(target_binary, self.loc_db)
        self.machine = Machine(self.container.arch)
        assert self.machine.dis_engine is not None

        self.mdis = self.machine.dis_engine(self.container.bin_stream, loc_db=self.loc_db)
        self.lifter = self.machine.lifter(self.loc_db)

    @property
    def arch(self) -> str:
        return str(self.container.arch)


def expr_int_to_int(expr: m2_expr.ExprInt) -> int:
    int_size = expr.size
    is_signed = expr.arg >= 2**(int_size - 1)
    if is_signed:
        result = -(2**int_size - expr.arg)
    else:
        result = expr.arg

    return int(result)

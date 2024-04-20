from dataclasses import dataclass
from typing import Self

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

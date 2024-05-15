from typing import Self

from binaryninja import BinaryView  # type:ignore
from binaryninja.log import Logger  # type:ignore
from binaryninja.plugin import BackgroundTaskThread  # type:ignore
from themida_unmutate.unwrapping import unwrap_functions
from themida_unmutate.symbolic_execution import disassemble_and_simplify_functions

from . import common, plugin

SUPPORTED_ARCHS = ["x86_64"]

logger = Logger(session_id=0, logger_name=plugin.NAME)


def deobfuscate_at_address(bv: BinaryView, address: int) -> None:
    DeobfuscateCodeAtAddressTask(bv=bv, address=address).start()


class DeobfuscateCodeAtAddressTask(BackgroundTaskThread):

    def __init__(self, bv: BinaryView, address: int):
        super().__init__(
            initial_progress_text=f"Deobfuscating code at 0x{address:x}",
            can_cancel=False,
        )
        self.bv = bv
        self.address = address

    def run(self: Self) -> None:
        if self.bv.arch is None:
            logger.log_error("Could not get architecture of current binary view")
            return

        arch = str(self.bv.platform.arch)
        if arch not in SUPPORTED_ARCHS:
            logger.log_error("Current binary view's architecture isn't supported")
            return
        logger.log_info(f"Deobfuscating code at 0x{self.address:x}")

        protected_func_addrs = [self.address]
        binary_data = common.get_binary_data(self.bv)
        miasm_ctx = common.create_miasm_context(arch, self.bv.original_base, binary_data)

        logger.log_info("Resolving mutated's function' address...")
        mutated_func_addrs = unwrap_functions(miasm_ctx, protected_func_addrs)

        # Disassemble mutated functions and simplify them
        logger.log_info("Deobfuscating mutated function...")
        simplified_func_asmcfgs = disassemble_and_simplify_functions(miasm_ctx, mutated_func_addrs)

        # Map protected functions' addresses to their corresponding simplified `AsmCFG`
        func_addr_to_simplified_cfg = {
            protected_func_addrs[i]: asm_cfg
            for i, asm_cfg in enumerate(simplified_func_asmcfgs)
        }

        # Rewrite the protected binary with the simplified function
        logger.log_info("Patching binary file...")
        common.rebuild_simplified_binary(miasm_ctx, func_addr_to_simplified_cfg, self.bv)

        # Relaunch analysis to take our changes into account
        self.bv.update_analysis()
        logger.log_info(f"Successfully simplified code at 0x{self.address:x}!")

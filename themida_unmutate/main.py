from argparse import ArgumentParser, Namespace

from themida_unmutate.logging import setup_logger, logger
from themida_unmutate.miasm_utils import MiasmContext
from themida_unmutate.rebuilding import rebuild_simplified_binary
from themida_unmutate.symbolic_execution import disassemble_and_simplify_functions
from themida_unmutate.unwrapping import unwrap_functions


def entry_point() -> None:
    # Parse command-line arguments
    args = parse_arguments()

    # Setup logging
    setup_logger(args.verbose)

    # Setup disassembler and lifter
    miasm_ctx = MiasmContext.from_binary_file(args.protected_binary)

    # Resolve mutated functions' addresses if needed
    protected_func_addrs = list(map(lambda addr: int(addr, 0), args.addresses))
    if not args.no_trampoline:
        logger.info("Resolving mutated's functions' addresses...")
        mutated_func_addrs = unwrap_functions(miasm_ctx, protected_func_addrs)
    else:
        # No trampolines to take care of, use target addresses directly
        mutated_func_addrs = protected_func_addrs

    # Disassemble mutated functions and simplify them
    logger.info("Deobfuscating mutated functions...")
    simplified_func_asmcfgs = disassemble_and_simplify_functions(miasm_ctx, mutated_func_addrs)

    # Map protected functions' addresses to their corresponding simplified `AsmCFG`
    func_addr_to_simplified_cfg = {
        protected_func_addrs[i]: asm_cfg
        for i, asm_cfg in enumerate(simplified_func_asmcfgs)
    }

    # Rewrite the protected binary with simplified functions
    logger.info("Rebuilding binary file...")
    rebuild_simplified_binary(miasm_ctx, func_addr_to_simplified_cfg, args.protected_binary, args.output,
                              args.reassemble_in_place)

    logger.info("Done! You can find your deobfuscated binary at '%s'" % args.output)


def parse_arguments() -> Namespace:
    """
    Parse command-line arguments.
    """
    parser = ArgumentParser(description="Automatic deobfuscation tool for Themida's mutation-based protection")
    parser.add_argument("protected_binary", help="Protected binary path")
    parser.add_argument("-a", "--addresses", nargs='+', help="Addresses of the functions to deobfuscate", required=True)
    parser.add_argument("-o", "--output", help="Output binary path", required=True)
    parser.add_argument("--no-trampoline", action='store_true', help="Disable function unwrapping")
    parser.add_argument("--reassemble-in-place",
                        action='store_true',
                        help="Rewrite simplified code over the mutated code "
                        "rather than in a new code section")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose logging")

    return parser.parse_args()


if __name__ == "__main__":
    entry_point()

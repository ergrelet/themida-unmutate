import functools
import re
from argparse import ArgumentParser
from typing import Any, Dict, Tuple
from future.utils import viewitems, viewvalues

import miasm.expression.expression as m2_expr
from miasm.arch.x86.sem import all_regs_ids, all_regs_ids_init
from miasm.core.asmblock import AsmConstraint, LocKey
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.ir.ir import IRCFG, AssignBlock, IRBlock, Lifter
from llvmlite import ir as llvm_ir
from miasm.expression.simplifications import expr_simp_high_to_explicit
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine

from .llvmconvert import LLVMType, LLVMContext_IRCompilation, LLVMFunction_IRCompilation

def main():
    parser = ArgumentParser("LLVM export example")
    parser.add_argument("target", help="Target binary")
    parser.add_argument("addr", help="Target address")
    parser.add_argument("--architecture", "-a", help="Force architecture")
    args = parser.parse_args()

    target_addr = int(args.addr, 0)

    loc_db = LocationDB()
    # This part focus on obtaining an IRCFG to transform #
    cont = Container.from_stream(open(args.target, 'rb'), loc_db)
    machine = Machine(args.architecture if args.architecture else cont.arch)
    lifter = machine.lifter(loc_db)
    dis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
    dis.follow_call = True
    asmcfg = dis.dis_multiblock(target_addr)

    # Lift asm to IR
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
    ircfg.simplify(expr_simp_high_to_explicit)

    print("Resolving mutated code portion address...")
    mutated_code_addr = resolve_mutated_portion_address(lifter, ircfg, target_addr)
    assert isinstance(mutated_code_addr, m2_expr.ExprInt)
    print(f"Mutated code is at {mutated_code_addr}")

    # Disassemble the mutated code portion
    dis.follow_call = False
    asmcfg_mutated = dis.dis_multiblock(mutated_code_addr.arg)

    # Enable callback and disassemble the target function
    dis.dis_block_callback = functools.partial(cb_redirect_tail_call, redirect_addr=mutated_code_addr.arg)
    asmcfg_target = dis.dis_multiblock(target_addr, blocks=asmcfg_mutated)

    # Lift asm to IR
    lifter = machine.lifter_model_call(loc_db)
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg_target)
    ircfg.simplify(expr_simp_high_to_explicit)

    # Determine function's stack layout from symexec of the entry block
    function_stack_size, function_stack_slots = determine_function_stack_layout(lifter, ircfg)
    print(f"Function stack size: {function_stack_size}")
    print("")

    # Simplify stack operations for LLVM
    apply_stack_to_reg_simplification(lifter, ircfg, function_stack_size, function_stack_slots)
 
    open("ir.dot", "w").write(ircfg.dot())

    ir = convert_to_llvm_ir(lifter, ircfg)
    # Get it back
    open("out.ll", "w").write(str(ir))

    # The optimized CFG can be seen with:
    # $ opt -O2 -dot-cfg -S out.ll && xdot cfg.test.dot

def resolve_mutated_portion_address(lifter: Lifter, ircfg: IRCFG, call_addr: int) -> int:
    # Instantiate a Symbolic Execution engine with default value for registers
    symb = SymbolicExecutionEngine(lifter)

    # Emulate until the next address cannot be resolved (`ret`, unresolved condition, etc.)
    cur_addr = symb.run_at(ircfg, call_addr)

    # First `cmp` -> eval to zero
    if not isinstance(cur_addr, m2_expr.ExprCond) or not isinstance(cur_addr.cond, m2_expr.ExprMem):
        raise Exception("Function doesn't behave as expected")
    # Value if condition is evaled zero
    symb.eval_updt_expr(m2_expr.ExprAssign(cur_addr.cond, m2_expr.ExprInt(0, cur_addr.cond.size)))
    target = cur_addr.src2
    cur_addr = symb.run_at(ircfg, target)

    # Second `cmp` -> eval to zero
    if not isinstance(cur_addr, m2_expr.ExprCond) or not isinstance(cur_addr.cond, m2_expr.ExprMem):
        raise Exception("Function doesn't behave as expected")
    # Value if condition is evaled zero
    symb.eval_updt_expr(m2_expr.ExprAssign(cur_addr.cond, m2_expr.ExprInt(0, cur_addr.cond.size)))
    target = cur_addr.src2
    cur_addr = symb.run_at(ircfg, target)

    # This time we should have the real mutated function address
    return cur_addr

jmp_replaced = 0

def cb_redirect_tail_call(mdis, cur_block, offsets_to_dis, redirect_addr: int) -> None:
    global jmp_replaced

    if jmp_replaced or len(cur_block.lines) < 1:
        return
    # We want to match a JMP, always the last line of a basic block
    last_instr = cur_block.lines[-1]
    if last_instr.name != 'JMP':
        return
    # The destination must be a location
    dst = last_instr.args[0]
    if not dst.is_loc():
        return
    
    # Update instruction's destination
    redirect_location: LocKey = mdis.loc_db.get_or_create_offset_location(redirect_addr)
    last_instr.args[0] = m2_expr.ExprLoc(redirect_location, dst.size)
    jmp_replaced = True

    # Update next offset to disassemble
    offsets_to_dis.clear()
    offsets_to_dis.add(redirect_addr)

    # Update next blocks to process in the disassembly engine
    cur_block.bto.clear()
    cur_block.add_cst(redirect_location, AsmConstraint.c_next)

def determine_function_stack_layout(lifter: Lifter, ircfg: IRCFG) -> Tuple[int, Dict[int, Any]]:
    # Instantiate a Symbolic Execution engine with default value for registers
    symex = SymbolicExecutionEngine(lifter)

    # Concretize RSP
    symex.apply_change(
        m2_expr.ExprId("RSP", 64),
        m2_expr.ExprInt(0, 64)
    )

    # Emulate until the next address cannot be resolved (`ret`, unresolved condition, etc.)
    symex.run_block_at(ircfg, ircfg.heads()[0])

    rsp = symex.eval_expr(m2_expr.ExprId("RSP", 64))
    assert isinstance(rsp, m2_expr.ExprInt)

    stack_size = -expr_int_to_int(rsp)
    stack_layout = {
        # x64 ABI: home to register parameters
        0x20:  symex.eval_expr(m2_expr.ExprMem(m2_expr.ExprInt(0x20, 64), 64)),
        0x18: symex.eval_expr(m2_expr.ExprMem(m2_expr.ExprInt(0x18, 64), 64)),
        0x10:  symex.eval_expr(m2_expr.ExprMem(m2_expr.ExprInt(0x10, 64), 64)),
        0x8:  symex.eval_expr(m2_expr.ExprMem(m2_expr.ExprInt(0x8, 64), 64)),
        # x86 ABI: return address
        0: m2_expr.ExprId("RET_ADDR", 64)
    }

    return stack_size, stack_layout

def apply_stack_to_reg_simplification(lifter: Lifter, ircfg: IRCFG, function_stack_size: int, function_stack_slots: Dict[int, Any]):
    # If there are multiple heads, it most likely means there's been an issue
    # during the lifting
    assert len(ircfg.heads()) == 1

    stack_offset_after_block = {}
    for loc_key in ircfg.walk_breadth_first_forward(ircfg.heads()[0]):
        block = ircfg.blocks[loc_key]

        # Get current stack pointer from successor block's
        # Note(ergrelet): this is a best effort algorithm which assumes the
        # function uses the stack as a compiler would (i.e., allocates stack in
        # the entry block and push/pop saved registers in entry/exit block)
        current_stack_pointer = 0
        for pred in ircfg.predecessors_iter(loc_key):
            pred_stack_pointer = stack_offset_after_block.get(pred)
            if pred_stack_pointer is not None:
                current_stack_pointer = pred_stack_pointer

        current_stack_slots = function_stack_slots
        irs = []

        # Init our symbols with all architecture known registers
        symbols_init =  {}
        for i, r in enumerate(all_regs_ids):
            symbols_init[r] = all_regs_ids_init[i]

        symex = SymbolicExecutionEngine(lifter, symbols_init)
        
        # Concretize RSP
        symex.apply_change(
            m2_expr.ExprId("RSP", 64),
            m2_expr.ExprInt(current_stack_pointer, 64)
        )
        # Concretize stack slots
        for slot_offset, slot_value in current_stack_slots.items():
            value = slot_value
            if value is not None:
                for size in [8, 16, 32, 64]:
                    var = get_stack_slot_expr(slot_offset, size)
                    if value.size != size:
                        sliced_value = m2_expr.ExprSlice(value, 0, size)
                        symex.apply_change(var, sliced_value)
                    else:
                        symex.apply_change(var, value)

        for assignblk in block:
            modified = False

            # Update symbolic state
            symex.eval_updt_assignblk(assignblk)

            assign_exprs = []
            local_stack_pointer = current_stack_pointer
            for assign_expr_dst, assign_expr_src in assignblk.iteritems():
                assign_expr = m2_expr.ExprAssign(assign_expr_dst, assign_expr_src)

                if isinstance(assign_expr.dst, m2_expr.ExprId) and assign_expr.dst.name == "RSP":
                    print(assign_expr)
                    if assignblk.instr.name == "RET":
                        # Ignore RSP update for RET instructions
                        modified = True
                        continue
                    if isinstance(assign_expr.src, m2_expr.ExprOp) and assign_expr.src.op == "call_func_stack":
                        # Keep as is
                        continue

                    # Concretize SRC and set current_stack_slot
                    ret_expr = symex.eval_expr(assign_expr.dst)
                    assert isinstance(ret_expr, m2_expr.ExprInt)

                    new_stack_pointer = expr_int_to_int(ret_expr)
                    if new_stack_pointer - current_stack_pointer >= 0:
                        offset = 8
                    else:
                        offset = -8
                    for stack_pointer in range(current_stack_pointer, new_stack_pointer, offset):
                        current_stack_slots[stack_pointer] = current_stack_slots.get(stack_pointer)
                    current_stack_pointer = new_stack_pointer
                    print(f"Update stack slot: {current_stack_pointer}")
            
                new_assignexpr = replace_stack_ptrs_expr(lifter, assign_expr, local_stack_pointer, current_stack_slots)
                if new_assignexpr != assign_expr:
                    if isinstance(new_assignexpr.dst, m2_expr.ExprId):
                        if new_assignexpr.dst.name.startswith("STACK"):
                            # [RSP + Y] = X
                            # Update stack
                            dst_stack_slot = stack_slot_name_to_offset(new_assignexpr.dst.name)
                            current_stack_slots[dst_stack_slot] = new_assignexpr.src
                            # Update IR
                            new_assignblk = set_stack_slot_value(dst_stack_slot, new_assignexpr.src)
                            assign_exprs += list(map(lambda t: m2_expr.ExprAssign(t[0], t[1]), new_assignblk.iteritems()))

                            print(f"Replaced DST STACK references for instruction: {assignblk.instr}")
                            print("")
                        else:
                            assign_exprs.append(new_assignexpr)
                            print(f"Replaced SRC STACK references for instruction: {assignblk.instr}")
                            print("")
                    else:
                        # X = [RSP + Y]
                        assign_exprs.append(new_assignexpr)
                        print(f"Replaced SRC STACK references for instruction: {assignblk.instr}")
                        print("")

                    modified = True
                else:
                    assign_exprs.append(assign_expr)
                    
            if not modified:
                # Keep original assignblk
                irs.append(assignblk)
                print(f"Original instruction kept: {assignblk.instr}")
            elif len(assign_exprs) > 0:
                # Replace original assignblkg
                irs.append(AssignBlock(assign_exprs))

        # Replace original IR block with a new block containing our modifications    
        new_irblock = IRBlock(ircfg.loc_db, loc_key, irs)
        ircfg.blocks[loc_key] = new_irblock

        # Check if the stack pointer has been modified in this block.
        # This means the original instruction was a "push/pop Y",
        # "add/sub rsp, X" or "ret"
        stack_offset_after_block[loc_key] = current_stack_pointer
        if current_stack_pointer != -function_stack_size:
            print(f"Stack modification detected in block {loc_key}")
            # assert current_stack_pointer <= 0


def replace_stack_ptrs_expr(lifter: Lifter, expr: m2_expr.Expr, current_stack_slot: int, stack_slots: Dict[int, Any])-> m2_expr.Expr:
    new_expr = expr.visit(functools.partial(cb_replace_stack_ptrs_expr, lifter=lifter, current_stack_slot=current_stack_slot, stack_slots=stack_slots))
    return new_expr

def cb_replace_stack_ptrs_expr(expr: m2_expr.Expr, lifter: Lifter, current_stack_slot: int, stack_slots: Dict[int, Any]) -> m2_expr.Expr:
    if isinstance(expr, m2_expr.ExprMem):
        return replace_stack_ptrs_exprmem(lifter, expr, current_stack_slot, stack_slots)
    return expr


def replace_stack_ptrs_exprmem(lifter: Lifter, expr: m2_expr.ExprMem, current_stack_slot: int, stack_slots: Dict[int, Any]) -> m2_expr.Expr:
    mem_ptr = expr.ptr

    if isinstance(mem_ptr, m2_expr.ExprId) and mem_ptr.name == "RSP":
        # [RSP]
        stack_slot_expr = get_stack_slot_expr(current_stack_slot, expr.size)
        return stack_slot_expr
    
    if isinstance(mem_ptr, m2_expr.ExprOp):
        # [ExprOp]
        is_rsp_relative = False
        for arg in mem_ptr.args:
            if isinstance(arg, m2_expr.ExprId) and arg.name == "RSP":
                is_rsp_relative = True

        # Concretize expression
        ret_expr = concretize_expr(lifter, mem_ptr, current_stack_slot, stack_slots)
        if isinstance(ret_expr, m2_expr.ExprInt):
            stack_slot = expr_int_to_int(ret_expr)
            if is_rsp_relative:
                # The expression contained only RSP and constant values
                stack_slot_expr = get_stack_slot_expr(stack_slot, expr.size)
                return stack_slot_expr
            return m2_expr.ExprMem(ret_expr, expr.size)
        
    return expr

def concretize_expr(lifter: Lifter, expr: m2_expr.Expr, current_stack_slot: int, stack_slots: Dict[int, Any]) -> m2_expr.Expr:
    symb = SymbolicExecutionEngine(lifter)
    
    # Concretize RSP
    symb.apply_change(
        m2_expr.ExprId("RSP", 64),
        m2_expr.ExprInt(current_stack_slot, 64)
    )
    # Concretize stack slots
    for slot_offset, slot_value in stack_slots.items():
        value = slot_value
        if value is not None:
            for size in [8, 16, 32, 64]:
                var = get_stack_slot_expr(slot_offset, size)
                if value.size != size:
                    sliced_value = m2_expr.ExprSlice(value, 0, size)
                    symb.apply_change(var, sliced_value)
                else:
                    symb.apply_change(var, value)

    return symb.eval_expr(expr)

def expr_int_to_int(expr: m2_expr.ExprInt) -> int:
    is_signed = expr.arg >= 2**63
    if is_signed:
        result = -(2**64 - expr.arg)
    else:
        result = expr.arg
    
    return result

def stack_slot_name_to_offset(name: str) -> int:
    _, value_as_str = name.split("_", 1)
    return int(value_as_str)

def get_stack_slot_expr(position: int, size: int) -> m2_expr.ExprId:
    # Ensure we're not missing unaligned positions
    assert position % 8 == 0
    return m2_expr.ExprId(f"STACK{size}_{position}", size)

def set_stack_slot_value(position: int, source: m2_expr.Expr) -> AssignBlock:
    supported_sizes = [8, 16, 32, 64]
    assign_exprs = []
    for size in supported_sizes:
        dst_var = get_stack_slot_expr(position, size)
        if source.size == size:
            src_var = source
        else:
            src_var = m2_expr.ExprSlice(source, 0, size)
        assign_exprs.append(m2_expr.ExprAssign(dst_var, src_var))
    
    return AssignBlock(assign_exprs)

def convert_to_llvm_ir(lifter: Lifter, ircfg: IRCFG) -> str:
    # Instantiate a context and the function to fill
    context = LLVMContext_IRCompilation()
    context.lifter = lifter

    # Abstract arguments/ret value and map them to native registers
    # following the corresponding ABI
    ABI_X64_MAPPING = {
        "ARG1": "RCX",
        "ARG2": "RDX",
        "ARG3": "R8",
        "ARG4": "R9",
        "RET_VALUE": "RAX",
    }
    function_args = [("ARG1", 32, LLVMType.IntType(32)), ("ARG2", 64, llvm_ir.PointerType(LLVMType.IntType(32)))]
    function_ret_value = ("RET_VALUE", 32, LLVMType.IntType(32))
    func = LLVMFunction_IRCompilation(context, name="reconstructed_function")
    func.ret_type = function_ret_value[2]
    for arg, size, ty in function_args:
        func.my_args.append((m2_expr.ExprId(arg, size), ty, arg))
    func.init_fc()

    # Here, as an example, we arbitrarily represent registers with global
    # variables. Locals allocas are used for the computation during the function,
    # and is finally saved in the aforementioned global variable.

    # In other words, for each registers:
    # entry:
    #     ...
    #     %reg_val_in = load i32 @REG
    #     %REG = alloca i32
    #     store i32 %reg_val_in, i32* %REG
    #     ...
    # exit:
    #     ...
    #     %reg_val_out = load i32 %REG
    #     store i32 %reg_val_out, i32* @REG
    #     ...

    all_regs = set()
    for block in viewvalues(ircfg.blocks):
        for irs in block.assignblks:
            for dst, src in viewitems(irs.get_rw(mem_read=True)):
                elem = src.union(set([dst]))
                all_regs.update(
                    x for x in elem
                    if x.is_id()
                )

     # Setup function arguments
    for arg_name, arg_size, arg_type in function_args:
        reg_name = ABI_X64_MAPPING.get(arg_name)
        if reg_name is None:
            # TODO: arg is on the stack
            pass

        if isinstance(arg_type, llvm_ir.IntType):
            # Truncate or zero extend
            if arg_size == 64:
                value = llvm_ir.NamedValue(context.mod, arg_type, name=str(arg_name))
            elif arg_size < 64:
                value = llvm_ir.NamedValue(context.mod, arg_type, name=str(arg_name))
                value = func.builder.zext(value, llvm_ir.IntType(64))
            else:
                raise "Unsupported argument size"
        elif isinstance(arg_type, llvm_ir.PointerType):
            value = llvm_ir.NamedValue(context.mod, arg_type, name=str(arg_name))
            value = func.builder.ptrtoint(value, llvm_ir.IntType(64))
        else:
            raise "Unsupported argument type"
        
        func.local_vars_pointers[reg_name] = func.builder.alloca(llvm_ir.IntType(64), name=reg_name)
        func.builder.store(value, func.local_vars_pointers[reg_name])

    reg_parameters = [ABI_X64_MAPPING[arg_name] for arg_name, _, _ in function_args]
    for var in all_regs:
        # Setup STACK slots
        if var.name.startswith("STACK"):
            func.local_vars_pointers[var.name] = func.builder.alloca(llvm_ir.IntType(var.size), name=var.name)
            func.builder.store(LLVMType.IntType(var.size)(0), func.local_vars_pointers[var.name])
            continue

        # Do not emit allocs for parameter registers in use
        if var.name in reg_parameters:
            continue

        # alloca reg = global reg
        data = context.mod.globals.get(str(var), None)
        if data is None:
            data = llvm_ir.GlobalVariable(context.mod,  LLVMType.IntType(var.size), name=str(var))
        data.initializer = LLVMType.IntType(var.size)(0)
        
        value = func.builder.load(data)
        func.local_vars_pointers[var.name] = func.builder.alloca(llvm_ir.IntType(var.size), name=var.name)
        func.builder.store(value, func.local_vars_pointers[var.name])

    # IRCFG is imported, without the final "ret void"
    func.from_ircfg(ircfg, append_ret=False)

    # Finish the function
    # TODO: handle multiple ret type
    ret_value = func.builder.load(func.local_vars_pointers[ABI_X64_MAPPING[function_ret_value[0]]])
    ret_value = func.builder.trunc(ret_value, function_ret_value[2])
    func.builder.ret(ret_value)

    ir = str(func)
    
    # Remove useless register/global
    replace_irdst = lambda match: ''
    ir = re.sub('.*[@%]"IRDst".*', replace_irdst, ir)

    # Dirty fix for a miasm IR translation bug
    replace_trunc = lambda match: f'zext i32 %"{match.group(1)}" to i64'
    ir = re.sub('trunc i32 %"(.*)" to i64', replace_trunc, ir)

    return ir

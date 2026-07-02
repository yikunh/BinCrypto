"""
通过分析调用者如何使用函数的返回值，推断函数的返回值类型 - Ghidra版本
"""
import os
import re


# Return-value registers and their aliases (x86-64)
RET_REG_NAMES = {"RAX", "EAX", "AX", "AL", "AH"}
RET_XMM_NAMES = {"XMM0", "XMM0_0"}


def _safe_name(funcname):
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def _is_ret_reg(reg_name):
    """Check if a register name is a return-value register (RAX or XMM0)"""
    if not reg_name:
        return None
    upper = reg_name.upper()
    if upper in RET_REG_NAMES:
        return "rax"
    if upper in RET_XMM_NAMES:
        return "xmm0"
    return None


def _ret_reg_in_text(ins_text):
    """Check if RAX or XMM0 appears in instruction text. Returns 'rax', 'xmm0', or None."""
    upper = ins_text.upper()
    if "XMM0" in upper:
        return "xmm0"
    for token in ("RAX", "EAX", "AX", "AL", "AH"):
        if token in upper:
            return "rax"
    return None


def _check_ret_reg_usage(ins_text, mnemonic):
    """Check if return register (RAX/XMM0) is read or written in this instruction.
    Returns: ('rax'|'xmm0', 'read') if ret reg is a source operand,
             ('rax'|'xmm0', 'write') if destination,
             None if ret reg not involved."""
    ret_reg = _ret_reg_in_text(ins_text)
    if not ret_reg:
        return None

    # XOR/SUB/SBB RAX,RAX → clearing, return value overwritten
    if mnemonic in ("XOR", "SUB", "SBB"):
        parts = ins_text.split(",")
        if len(parts) == 2:
            op1 = parts[0].strip().upper()
            op2 = parts[1].strip().upper()
            if _ret_reg_in_text(op1) and _ret_reg_in_text(op1) == _ret_reg_in_text(op2):
                return (ret_reg, "write")

    # TEST/CMP: always reads the operand
    if mnemonic in ("TEST", "CMP"):
        return (ret_reg, "read")

    # For other instructions, check if ret reg is in the first operand (destination) or later (source)
    # Strip mnemonic prefix to get operands
    mnemonic_len = len(mnemonic)
    operands_part = ins_text[mnemonic_len:].strip()

    # Check if ret reg appears in first operand (destination)
    comma_pos = operands_part.find(",")
    if comma_pos > 0:
        first_op = operands_part[:comma_pos]
        rest = operands_part[comma_pos + 1:]
    else:
        first_op = operands_part
        rest = ""

    if _ret_reg_in_text(first_op):
        return (ret_reg, "write")
    elif _ret_reg_in_text(rest) or _ret_reg_in_text(operands_part):
        return (ret_reg, "read")

    return None


def check_if_ret_reg_used_after_call(flat_api, call_addr, caller_func):
    """Check if RAX or XMM0 is used after a call instruction within the same basic block"""
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    current_program = flat_api.getCurrentProgram()
    listing = current_program.getListing()

    # Get next instruction after the call
    next_off = call_addr.getOffset()
    # Get the call instruction to find its length
    call_ins = listing.getInstructionAt(call_addr)
    if not call_ins:
        return None
    next_off = call_addr.getOffset() + call_ins.getLength()
    next_addr = flat_api.toAddr(next_off)
    ins = listing.getInstructionAt(next_addr)
    if not ins:
        return None

    # Find the basic block containing this instruction
    block_model = BasicBlockModel(current_program)
    monitor = TaskMonitor.DUMMY
    body = caller_func.getBody()
    blocks = block_model.getCodeBlocksContaining(body, monitor)

    current_block = None
    for block in blocks:
        if block.getMinAddress().getOffset() <= next_off <= block.getMaxAddress().getOffset():
            current_block = block
            break

    if not current_block:
        return None

    block_end = current_block.getMaxAddress().getOffset()

    # Scan instructions within current block starting from next_addr
    cur_addr = next_addr
    while cur_addr.getOffset() <= block_end:
        ins = listing.getInstructionAt(cur_addr)
        if not ins:
            break

        mnemonic = ins.getMnemonicString().upper()
        ins_text = ins.toString()

        # If we hit another call before using return reg, the return value is not used
        if mnemonic == "CALL":
            return None

        # Skip NOP
        if mnemonic == "NOP":
            cur_addr = flat_api.toAddr(cur_addr.getOffset() + ins.getLength())
            continue

        usage = _check_ret_reg_usage(ins_text, mnemonic)
        if usage:
            ret_reg, mode = usage
            if mode == "read":
                return ret_reg
            else:
                # write: ret reg being overwritten → not used
                return None

        cur_addr = flat_api.toAddr(cur_addr.getOffset() + ins.getLength())

    return ""


def dump_func_ret_value(flat_api, program, funcname, funcStartAddr):
    current_program = flat_api.getCurrentProgram()
    function_manager = current_program.getFunctionManager()
    ref_manager = current_program.getReferenceManager()

    target_addr = flat_api.toAddr(funcStartAddr)
    refs = ref_manager.getReferencesTo(target_addr)

    ret_value_determined = False
    result = "void"

    for ref in refs:
        if not ref.getReferenceType().isCall():
            continue

        caller_addr = ref.getFromAddress()
        caller_func = function_manager.getFunctionContaining(caller_addr)
        if not caller_func:
            continue

        res = check_if_ret_reg_used_after_call(flat_api, caller_addr, caller_func)
        if res == "rax" or res == "xmm0":
            ret_value_determined = True
            result = res
            break

    os.makedirs("./" + program + "/dump", exist_ok=True)
    fp = open("./" + program + "/dump/" + _safe_name(funcname) + "-dumpPrototype.txt", "a")
    fp.write(result + "\n")
    fp.close()

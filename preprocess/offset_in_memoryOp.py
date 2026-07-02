"""
识别并记录内存操作指令中的负偏移量 - Ghidra版本
"""
import os
import re


def _safe_name(funcname):
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def _get_scalar_value(ins, op_idx):
    """Get the scalar (immediate/displacement) value for an instruction operand.
    Returns the scalar value or None."""
    try:
        op_objs = ins.getOpObjects(op_idx)
        for obj in op_objs:
            try:
                # Ghidra Scalar object
                val = obj.getValue()
                if val is not None:
                    return val
            except AttributeError:
                pass
    except Exception:
        pass
    # Fallback: try getScalar
    try:
        scalar = ins.getScalar(op_idx)
        if scalar:
            return scalar.getValue()
    except Exception:
        pass
    return None


def record_inst_offset_in_memoryOp(program, funcname, offset):
    """Check if offset is negative (high 32 bits set) and record it"""
    # Normalize to unsigned 64-bit
    if offset < 0:
        offset = offset & 0xffffffffffffffff

    if offset & 0xffffffff00000000:
        recognized = offset & 0xffffffff
        normalized = ((0xffffffffffffffff ^ offset) + 1) & 0xffffffffffffffff
        fp = open("./" + program + "/dump/" + _safe_name(funcname) + "-negOffsetInMemoryOp.txt", "a")
        fp.write("recognized offset: " + str(recognized) + ", normalized offset: " + str(normalized) + "\n")
        fp.close()


def _is_memory_operand(ins, op_idx):
    """Check if operand is a memory reference (x86: contains '[' or 'PTR')"""
    try:
        ins_str = ins.toString()
        mnemonic = ins.getMnemonicString()
        rest = ins_str[len(mnemonic):].strip()
        parts = rest.split(',')
        if op_idx < len(parts):
            part = parts[op_idx].strip().upper()
            if '[' in part or 'PTR' in part:
                return True
    except Exception:
        pass
    return False


def dump_offset_in_memoryOp(flat_api, program, funcname, funcStartAddr):
    current_program = flat_api.getCurrentProgram()
    listing = current_program.getListing()
    function_manager = current_program.getFunctionManager()

    func = function_manager.getFunctionContaining(flat_api.toAddr(funcStartAddr))
    if not func:
        return

    os.makedirs("./" + program + "/dump", exist_ok=True)

    instructions = listing.getInstructions(func.getBody(), True)
    for ins in instructions:
        for i in range(ins.getNumOperands()):
            if _is_memory_operand(ins, i):
                offset = _get_scalar_value(ins, i)
                if offset is not None:
                    record_inst_offset_in_memoryOp(program, funcname, offset)

"""
输出函数内所有基本块的起始地址偏移 - Ghidra版本
"""
import os
import re


def _safe_name(funcname):
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def dump_func_bb_offset(flat_api, program, funcname, func, binary_start_ea):
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    current_program = flat_api.getCurrentProgram()
    block_model = BasicBlockModel(current_program)
    monitor = TaskMonitor.DUMMY

    blocks = block_model.getCodeBlocksContaining(func.getBody(), monitor)

    os.makedirs("./" + program + "/dump", exist_ok=True)
    fp = open("./" + program + "/dump/" + _safe_name(funcname) + "-dumpBBOffset.txt", "w")

    for block in blocks:
        offset = block.getMinAddress().getOffset() - binary_start_ea
        fp.write("bb offset: " + str(offset) + "\n")
    fp.close()

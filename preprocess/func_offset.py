"""
输出函数的偏移信息和内联标记 - Ghidra版本
"""
import os
import re


def _safe_name(funcname):
    """Replace characters that are invalid in Windows filenames"""
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def dump_func_offset(flat_api, program, funcname, funcStartAddr, funcEndAddr, inlineList):
    current_program = flat_api.getCurrentProgram()
    binary_start_ea = current_program.getImageBase().getOffset()

    os.makedirs("./" + program + "/dump", exist_ok=True)

    safe_name = _safe_name(funcname)
    fp = open("./" + program + "/dump/" + safe_name + "-dumpOffset.txt", "w")
    fp.write("function offset: " + str(funcStartAddr - binary_start_ea) + "\n")
    fp.close()

    global_fp = open("./" + program + "/dump/funcUnitList.txt", "a")
    global_fp.write("start offset: " + str(funcStartAddr - binary_start_ea) +
                    ", end offset: " + str(funcEndAddr - binary_start_ea + 1) +
                    ", should be inlined: " + str(int(funcStartAddr in inlineList)) +
                    ", name: " + funcname + "\n")
    global_fp.close()

"""
识别并记录函数中没有后继的基本块（终止块）- Ghidra版本
"""
import os
import re


def _safe_name(funcname):
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def dump_force_stop_block(flat_api, program, func, binary_start_ea):
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    current_program = flat_api.getCurrentProgram()
    block_model = BasicBlockModel(current_program)
    monitor = TaskMonitor.DUMMY

    blocks = block_model.getCodeBlocksContaining(func.getBody(), monitor)

    os.makedirs("./" + program + "/dump", exist_ok=True)
    fp = open("./" + program + "/dump/forceStopBlock.txt", "a")

    for block in blocks:
        dests = block.getDestinations(monitor)
        has_succ = False
        while dests.hasNext():
            dest_ref = dests.next()
            dest_block = dest_ref.getDestinationBlock()
            if dest_block and func.getBody().contains(dest_block.getMinAddress()):
                has_succ = True
                break

        if not has_succ:
            start_off = block.getMinAddress().getOffset() - binary_start_ea
            end_off = block.getMaxAddress().getOffset() - binary_start_ea + 1
            fp.write("start offset: " + str(start_off) + ", end offset: " + str(end_off) + "\n")
    fp.close()

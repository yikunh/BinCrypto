"""
识别并记录函数中具有多个前驱的基本块（检查点块）- Ghidra版本
"""
import os
import re


def _safe_name(funcname):
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def dump_checkpoint_block(flat_api, program, funcname, func, binary_start_ea):
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    current_program = flat_api.getCurrentProgram()
    block_model = BasicBlockModel(current_program)
    monitor = TaskMonitor.DUMMY

    blocks_iter = block_model.getCodeBlocksContaining(func.getBody(), monitor)

    blocks = []
    predecessors_map = {}

    for block in blocks_iter:
        blocks.append(block)
        start_off = block.getMinAddress().getOffset()

        dests = block.getDestinations(monitor)
        while dests.hasNext():
            dest_ref = dests.next()
            dest_block = dest_ref.getDestinationBlock()
            if dest_block and func.getBody().contains(dest_block.getMinAddress()):
                to_off = dest_block.getMinAddress().getOffset()
                if to_off not in predecessors_map:
                    predecessors_map[to_off] = 0
                predecessors_map[to_off] += 1

    os.makedirs("./" + program + "/dump", exist_ok=True)
    fp = open("./" + program + "/dump/" + _safe_name(funcname) + "-dumpCheckpoint.txt", "w")

    for block in blocks:
        start_off = block.getMinAddress().getOffset()
        pred_count = predecessors_map.get(start_off, 0)
        if pred_count >= 2:
            fp.write("checkpoint offset: " + str(start_off - binary_start_ea) + "\n")
    fp.close()

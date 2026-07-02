"""
输出函数内每个基本块及其所有前驱块的起始地址偏移 - Ghidra版本
"""
import os
import re


def _safe_name(funcname):
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def dump_bb_predcessor(flat_api, program, funcname, func, binary_start_ea):
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    current_program = flat_api.getCurrentProgram()
    block_model = BasicBlockModel(current_program)
    monitor = TaskMonitor.DUMMY

    blocks_iter = block_model.getCodeBlocksContaining(func.getBody(), monitor)

    blocks = []
    predecessors_map = {}

    # Build block list and predecessor map
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
                    predecessors_map[to_off] = []
                if block not in predecessors_map[to_off]:
                    predecessors_map[to_off].append(block)

    os.makedirs("./" + program + "/dump", exist_ok=True)
    fp = open("./" + program + "/dump/" + _safe_name(funcname) + "-dumpBBandPredsOffset.txt", "w")

    for block in blocks:
        start_off = block.getMinAddress().getOffset()
        fp.write("bb offset: " + str(start_off - binary_start_ea) + "\n")
        preds = predecessors_map.get(start_off, [])
        for pred in preds:
            fp.write("preds offset: " + str(pred.getMinAddress().getOffset() - binary_start_ea) + "\n")
    fp.close()

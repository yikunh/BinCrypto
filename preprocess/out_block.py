"""
识别函数中所有具有两个后继（conditional jump）的基本块，
并记录这些块的边界信息和两个后继块的地址 - Ghidra版本
"""
import os
import re


def _safe_name(funcname):
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def _check_if_preds_only_has_one_successor(block, successors_map, get_preds, jmp_block_list, out_block_list, out_block_pair):
    """递归检查前驱块是否只有一个后继"""
    preds = get_preds(block)
    for pred in preds:
        pred_succs = successors_map.get(pred, [])
        if len(pred_succs) == 1 and pred not in jmp_block_list:
            jmp_block_list.append(pred)
            out_block_list.append(out_block_pair)
            _check_if_preds_only_has_one_successor(pred, successors_map, get_preds, jmp_block_list, out_block_list, out_block_pair)


def find_out_block_for_all_block_in_func(flat_api, func):
    """Find all blocks with 2 successors (conditional jumps)"""
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    current_program = flat_api.getCurrentProgram()
    block_model = BasicBlockModel(current_program)
    monitor = TaskMonitor.DUMMY

    blocks_iter = block_model.getCodeBlocksContaining(func.getBody(), monitor)

    blocks = []
    successors_map = {}
    predecessors_map = {}

    for block in blocks_iter:
        blocks.append(block)
        start_off = block.getMinAddress().getOffset()

        succs = []
        dests = block.getDestinations(monitor)
        while dests.hasNext():
            dest_ref = dests.next()
            dest_block = dest_ref.getDestinationBlock()
            if dest_block:
                to_off = dest_block.getMinAddress().getOffset()
                # Only count if destination is within this function
                if func.getBody().contains(flat_api.toAddr(to_off)):
                    succs.append(to_off)
                    if to_off not in predecessors_map:
                        predecessors_map[to_off] = []
                    predecessors_map[to_off].append(block)

        successors_map[block] = succs

    def get_preds(block):
        start_off = block.getMinAddress().getOffset()
        return predecessors_map.get(start_off, [])

    jmp_block_list = []
    out_block_list = []

    for block in blocks:
        succs = successors_map.get(block, [])
        if len(succs) == 2:
            jmp_block_list.append(block)
            out_block_pair = (succs[0], succs[1])
            out_block_list.append(out_block_pair)
            _check_if_preds_only_has_one_successor(block, successors_map, get_preds, jmp_block_list, out_block_list, out_block_pair)

    return jmp_block_list, out_block_list


def dump_find_out_block_for_all_block_in_func(flat_api, program, funcname, func, binary_start_ea):
    jmp_block_list, out_block_list = find_out_block_for_all_block_in_func(flat_api, func)

    os.makedirs("./" + program + "/dump", exist_ok=True)
    fp = open("./" + program + "/dump/" + _safe_name(funcname) + "-jumpBlock.txt", "w")

    for idx in range(len(jmp_block_list)):
        block = jmp_block_list[idx]
        out = out_block_list[idx]

        block_start = block.getMinAddress().getOffset()
        block_end = block.getMaxAddress().getOffset()
        out0 = out[0]
        out1 = out[1]

        fp.write("start offset: " + str((block_start - binary_start_ea) & 0xffffffff) +
                ", end offset: " + str((block_end - binary_start_ea + 1) & 0xffffffff) +
                ", one out offset: " + str((out0 - binary_start_ea) & 0xffffffff) +
                ", another out offset: " + str((out1 - binary_start_ea) & 0xffffffff) + "\n")
    fp.close()

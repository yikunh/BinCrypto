"""
以BFS顺序输出函数中所有基本块的起始地址偏移 - Ghidra版本
"""
import os
import re


def _safe_name(funcname):
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def dump_instruction_address_offset_list(flat_api, program, funcname, func, binary_start_ea):
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    current_program = flat_api.getCurrentProgram()
    block_model = BasicBlockModel(current_program)
    monitor = TaskMonitor.DUMMY

    blocks_iter = block_model.getCodeBlocksContaining(func.getBody(), monitor)

    blocks = []
    block_by_start = {}
    successors_map = {}

    for block in blocks_iter:
        blocks.append(block)
        block_by_start[block.getMinAddress().getOffset()] = block

        succs = []
        dests = block.getDestinations(monitor)
        while dests.hasNext():
            dest_ref = dests.next()
            dest_block = dest_ref.getDestinationBlock()
            if dest_block and func.getBody().contains(dest_block.getMinAddress()):
                succs.append(dest_block)
        successors_map[block] = succs

    # Find entry block (block whose start equals function entry)
    func_start = func.getEntryPoint().getOffset()
    entry_block = block_by_start.get(func_start)
    if not entry_block:
        # Fallback: use first block
        entry_block = blocks[0] if blocks else None

    if not entry_block:
        return

    # BFS traversal
    os.makedirs("./" + program + "/dump", exist_ok=True)
    fp = open("./" + program + "/dump/" + _safe_name(funcname) + "-instAddrList.txt", "w")

    wl_stack = [entry_block]
    analyzed = set()

    while wl_stack:
        block = wl_stack.pop()
        block_id = block.getMinAddress().getOffset()
        if block_id in analyzed:
            continue
        analyzed.add(block_id)

        offset = block.getMinAddress().getOffset() - binary_start_ea
        fp.write("address offset: " + str(offset) + "\n")

        for succ in successors_map.get(block, []):
            wl_stack.insert(0, succ)

    fp.close()

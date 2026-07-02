"""
检测函数中的循环后向边（loop back edge）- Ghidra版本
使用Tarjan SCC + DFST + DFO + DOM分析
"""
import os
import re
from collections import defaultdict


def _safe_name(funcname):
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


class Graph:
    def __init__(self, vertices):
        self.V = vertices
        self.graph = defaultdict(list)
        self.Time = 0

    def addEdge(self, u, v):
        self.graph[u].append(v)

    def SCCUtil(self, u, low, disc, stackMember, st, loop_body_list, idBlockMap):
        disc[u] = self.Time
        low[u] = self.Time
        self.Time += 1
        stackMember[u] = True
        st.append(u)

        for v in self.graph[u]:
            if disc[v] == -1:
                self.SCCUtil(v, low, disc, stackMember, st, loop_body_list, idBlockMap)
                low[u] = min(low[u], low[v])
            elif stackMember[v]:
                low[u] = min(low[u], disc[v])

        loop_body = []
        w = -1
        if low[u] == disc[u]:
            while w != u:
                w = st.pop()
                loop_body.append(idBlockMap[w])
                stackMember[w] = False

        if len(loop_body) > 1:
            loop_body_list.append(loop_body)

    def SCC(self, idBlockMap):
        disc = [-1] * self.V
        low = [-1] * self.V
        stackMember = [False] * self.V
        st = []

        loop_body_list = []
        for i in range(self.V):
            if disc[i] == -1:
                self.SCCUtil(i, low, disc, stackMember, st, loop_body_list, idBlockMap)
        return loop_body_list


def _build_block_maps(blocks_iter, func, monitor):
    """Build block list, ID mapping, address mapping, successor/predecessor maps"""
    blocks = []
    idBlockMap = {}
    addrBlockMap = {}
    successors_map = {}
    index_map = {}

    for block in blocks_iter:
        blocks.append(block)
        block_addr = block.getMinAddress().getOffset()
        idBlockMap[block_addr] = block
        addrBlockMap[block_addr] = block

        succs = []
        dests = block.getDestinations(monitor)
        while dests.hasNext():
            dest_ref = dests.next()
            dest_block = dest_ref.getDestinationBlock()
            if dest_block and func.getBody().contains(dest_block.getMinAddress()):
                succs.append(dest_block)
        successors_map[block] = succs

    # Build integer index mapping for Graph class (bidirectional)
    reverse_index_map = {}  # int -> block object
    for i, block in enumerate(blocks):
        addr = block.getMinAddress().getOffset()
        index_map[addr] = i
        reverse_index_map[i] = block

    # Build predecessor map
    predecessors_map = {}
    for block in blocks:
        block_addr = block.getMinAddress().getOffset()
        for succ in successors_map.get(block, []):
            succ_addr = succ.getMinAddress().getOffset()
            if succ_addr not in predecessors_map:
                predecessors_map[succ_addr] = []
            predecessors_map[succ_addr].append(block)

    return blocks, idBlockMap, addrBlockMap, successors_map, predecessors_map, index_map, reverse_index_map


def _get_preds(block, predecessors_map):
    return predecessors_map.get(block.getMinAddress().getOffset(), [])


def _get_succs(block, successors_map):
    return successors_map.get(block, [])


def DFS_v2(fc_blocks, successors_map, path, path_with_block_obj, back_edge, loop_path, loop_path_block_id):
    """Iterative DFS to find back edges (nature loops)"""
    WL_stack = [(fc_blocks[0], None)]
    analyzed_block = []

    while WL_stack:
        block, pred = WL_stack.pop()
        if pred is not None:
            addr = path.pop()
            obj = path_with_block_obj.pop()
            while pred.getMinAddress().getOffset() != addr:
                addr = path.pop()
                obj = path_with_block_obj.pop()
            path.append(addr)
            path_with_block_obj.append(obj)

        if block.getMinAddress().getOffset() in path:
            back_edge[path[-1]] = block.getMinAddress().getOffset()
            loop_path_item = []
            loop_path_item_block_id = []
            findLoopStart = False
            for item in path_with_block_obj:
                if item.getMinAddress().getOffset() == block.getMinAddress().getOffset():
                    findLoopStart = True
                if findLoopStart:
                    loop_path_item.append(item)
                    loop_path_item_block_id.append(item.getMinAddress().getOffset())
            loop_path.append(loop_path_item)
            loop_path_block_id.append(loop_path_item_block_id)

        path.append(block.getMinAddress().getOffset())
        path_with_block_obj.append(block)

        if block.getMinAddress().getOffset() in analyzed_block:
            path.pop()
            path_with_block_obj.pop()
            continue
        analyzed_block.append(block.getMinAddress().getOffset())

        succs = list(_get_succs(block, successors_map))
        succs_rev = []
        for s in succs:
            succs_rev.insert(0, s)

        for successor in succs_rev:
            WL_stack.append((successor, block))

        if len(succs) == 0:
            path.pop()
            path_with_block_obj.pop()


def DFS_v3(block, g, successors_map, index_map):
    """DFS to build subgraph for SCC"""
    WL_stack = [block]
    analyzed_block = []

    while WL_stack:
        b = WL_stack.pop()
        analyzed_block.append(b.getMinAddress().getOffset())
        for successor in _get_succs(b, successors_map):
            g.addEdge(index_map[b.getMinAddress().getOffset()],
                      index_map[successor.getMinAddress().getOffset()])
            if successor.getMinAddress().getOffset() in analyzed_block:
                continue
            WL_stack.append(successor)


def Union(A, B):
    res = list(A)
    for item in B:
        if item not in res:
            res.append(item)
    return res


def Intersection(A, B):
    res = []
    for item in A:
        if item in B:
            res.append(item)
    return res


def MeetInto(block, OUT, ignore_preds, predecessors_map):
    res = []
    isFirst = True
    for pred in _get_preds(block, predecessors_map):
        pred_addr = pred.getMinAddress().getOffset()
        if pred_addr in ignore_preds:
            continue
        if isFirst:
            res = list(OUT[pred_addr])
            isFirst = False
        else:
            res = Intersection(res, OUT[pred_addr])
    return res


def Transfer(block, IN):
    return Union(list(IN), [block])


def DOM_By_Found_ignore_entry(nodeSet, ignore_preds, entry_addr, predecessors_map):
    OUT = {}
    IN = {}

    for block in nodeSet:
        if block.getMinAddress().getOffset() == entry_addr:
            OUT[block.getMinAddress().getOffset()] = [block]
        else:
            OUT[block.getMinAddress().getOffset()] = nodeSet

    isAnyItemInDomChanged = True
    while isAnyItemInDomChanged:
        isAnyItemInDomChanged = False
        for block in nodeSet:
            if block.getMinAddress().getOffset() == entry_addr:
                continue
            previous_out_len = len(OUT[block.getMinAddress().getOffset()])
            IN[block.getMinAddress().getOffset()] = MeetInto(block, OUT, ignore_preds, predecessors_map)
            OUT[block.getMinAddress().getOffset()] = Transfer(block, IN[block.getMinAddress().getOffset()])
            if previous_out_len != len(OUT[block.getMinAddress().getOffset()]):
                isAnyItemInDomChanged = True
    return OUT


def find_back_according_loop_body_dom(Dom, successors_map, loop_back_edge):
    for blockID in Dom.keys():
        for succ in _get_succs(Dom[blockID][0] if Dom[blockID] else None, successors_map):
            for item in Dom[blockID]:
                if item.getMinAddress().getOffset() == succ.getMinAddress().getOffset():
                    pair = (blockID, succ.getMinAddress().getOffset())
                    if pair not in loop_back_edge:
                        loop_back_edge.append(pair)
                    break

    # Fix: iterate properly over the Dom dict
    for block_addr in Dom.keys():
        for succ in _get_succs(Dom[block_addr][0] if Dom.get(block_addr) else None, successors_map):
            for item in Dom[block_addr]:
                if item.getMinAddress().getOffset() == succ.getMinAddress().getOffset():
                    pair = (block_addr, succ.getMinAddress().getOffset())
                    if pair not in loop_back_edge:
                        loop_back_edge.append(pair)
                    break


def dump_loop_back_edge(flat_api, program, funcname, func, binary_start_ea):
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    current_program = flat_api.getCurrentProgram()
    block_model = BasicBlockModel(current_program)
    monitor = TaskMonitor.DUMMY

    blocks_iter = block_model.getCodeBlocksContaining(func.getBody(), monitor)

    blocks, idBlockMap, addrBlockMap, successors_map, predecessors_map, index_map, rev_idx_map = \
        _build_block_maps(blocks_iter, func, monitor)

    if not blocks:
        return

    FC_BLOCKS = blocks

    # Fix: re-implement find_back_according_loop_body_dom with proper block lookup
    def _find_back_edges(Dom, loop_back_edge):
        for block_addr in Dom.keys():
            block = idBlockMap.get(block_addr)
            if not block:
                continue
            for succ in _get_succs(block, successors_map):
                for item in Dom[block_addr]:
                    if item.getMinAddress().getOffset() == succ.getMinAddress().getOffset():
                        pair = (block_addr, succ.getMinAddress().getOffset())
                        if pair not in loop_back_edge:
                            loop_back_edge.append(pair)
                        break

    analyzed_block = []
    path = []
    path_with_block_obj = []
    back_edge = {}
    loop_path = []
    loop_path_block_id = []
    DFS_v2(FC_BLOCKS, successors_map, path, path_with_block_obj, back_edge, loop_path, loop_path_block_id)

    loop_back_edge_final = []
    loop_body_list = []
    for key in back_edge.keys():
        loop_back_edge_final.append((key, back_edge[key]))

        tmp_g = Graph(len(FC_BLOCKS))
        DFS_v3(addrBlockMap[key], tmp_g, successors_map, index_map)
        tmp_loop_body_list = tmp_g.SCC(rev_idx_map)

        for tmp_loop_body in tmp_loop_body_list:
            isSame = False
            for loop_body in loop_body_list:
                for block in loop_body:
                    if tmp_loop_body[0].getMinAddress().getOffset() == block.getMinAddress().getOffset():
                        isSame = True
                        break
                if isSame:
                    break
            if not isSame:
                loop_body_list.append(tmp_loop_body)

    loop_entry_list = []
    for loop_body in loop_body_list:
        ignore_preds = []
        loop_entry = []
        for current_block in loop_body:
            for pred in _get_preds(current_block, predecessors_map):
                inLoopBody = False
                for lb in loop_body:
                    if pred.getMinAddress().getOffset() == lb.getMinAddress().getOffset():
                        inLoopBody = True
                        break
                if not inLoopBody:
                    ignore_preds.append(pred.getMinAddress().getOffset())
                    alreadyInLoopEntry = False
                    for entry_block in loop_entry:
                        if entry_block.getMinAddress().getOffset() == current_block.getMinAddress().getOffset():
                            alreadyInLoopEntry = True
                    if not alreadyInLoopEntry:
                        loop_entry.append(current_block)
        loop_entry_list.append((loop_entry, loop_body, ignore_preds))

    for loop_entry, loop_body, ignore_preds in loop_entry_list:
        loop_entry_addr_list = []
        for entry in loop_entry:
            loop_entry_addr_list.append(entry.getMinAddress().getOffset())

        for entry_addr in loop_entry_addr_list:
            Dom = DOM_By_Found_ignore_entry(loop_body, ignore_preds, entry_addr, predecessors_map)
            _find_back_edges(Dom, loop_back_edge_final)

    if len(loop_back_edge_final) > 0:
        os.makedirs("./" + program + "/dump", exist_ok=True)
        fp = open("./" + program + "/dump/" + _safe_name(funcname) + "-loopBackEdge.txt", "w")
        for item in loop_back_edge_final:
            fp.write("Loop back edge from: " + str(item[0] - binary_start_ea) +
                     " to: " + str(item[1] - binary_start_ea) + "\n")
        fp.close()

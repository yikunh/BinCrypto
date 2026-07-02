"""
分析二进制程序中的函数，
基于启发式规则判断哪些函数应该被标记为"需要内联" - Ghidra版本
"""
import os

# 调用者大小阈值：如果函数≤10个基本块，检查其被调用者是否需要内联
checkIfCallersCalleeNeedInlineCallerSizeThreshold = 10
# 被调用者数量阈值：如果被调用者数量≤2，检查是否需要内联
checkIfCallersCalleeNeedInlineCalleeNumberThreshold = 2
# 被引用次数阈值：如果被调用者被引用次数≤10，可能内联
checkIfCallersCalleeNeedInlineCalleeRefedThreshold = 10
# 被调用者大小阈值：如果被调用者<25个基本块，可能内联
checkIfCallersCalleeNeedInlineCalleeSizeThreshold = 25
# 单块单调用阈值：调用者只有1个块且只有1个被调用者，且被调用者≤10个块
checkIfCallerOneBlockAndOnlyCalleeSizeThreshold = 10


def GetFuncBlockSize(func, current_program):
    """计算函数实际拥有的基本块数量，排除掉跳转调用引入的块"""
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitor

    block_model = BasicBlockModel(current_program)
    monitor = TaskMonitor.DUMMY
    blocks = block_model.getCodeBlocksContaining(func.getBody(), monitor)

    func_start = func.getEntryPoint().getOffset()
    func_end = func.getBody().getMaxAddress().getOffset()

    block_size = 0
    for block in blocks:
        if block.getMinAddress().getOffset() >= func_start and block.getMinAddress().getOffset() < func_end:
            block_size += 1
    return block_size


def check_all_func_if_it_need_inline(flat_api, program, pltStart, pltEnd, inlineList):
    current_program = flat_api.getCurrentProgram()
    function_manager = current_program.getFunctionManager()
    listing = current_program.getListing()
    ref_manager = current_program.getReferenceManager()

    functions = function_manager.getFunctions(True)

    for func in functions:
        funcname = func.getName()
        start = func.getEntryPoint().getOffset()
        end = func.getBody().getMaxAddress().getOffset()

        callerBlockSize = GetFuncBlockSize(func, current_program)

        # Get all callee list (only non-libc callees, i.e., outside PLT range)
        calleeList = []
        allLibcCall = False

        instructions = listing.getInstructions(func.getBody(), True)
        for ins in instructions:
            ins_addr = ins.getAddress()
            flow_type = ins.getFlowType()
            if flow_type.isCall():
                refs = ref_manager.getReferencesFrom(ins_addr)
                for ref in refs:
                    to_addr = ref.getToAddress()
                    calleeAddr = to_addr.getOffset()
                    # Skip external addresses (Ghidra resolves some PLT calls to external space)
                    if to_addr.isExternalAddress():
                        continue
                    # Skip if callee is inside current function (block-local jump)
                    if calleeAddr >= start and calleeAddr < end:
                        continue
                    # Only keep non-libc callees (outside PLT range)
                    if (calleeAddr < pltStart or calleeAddr >= pltEnd):
                        if calleeAddr not in calleeList:
                            calleeList.append(calleeAddr)

        if len(calleeList) == 0:
            allLibcCall = True

        # Check if in this function, it has callee should be inlined.
        if (callerBlockSize <= checkIfCallersCalleeNeedInlineCallerSizeThreshold
                and len(calleeList) <= checkIfCallersCalleeNeedInlineCalleeNumberThreshold):
            for calleeAddr in calleeList:
                if calleeAddr not in inlineList:
                    callee_func = function_manager.getFunctionContaining(flat_api.toAddr(calleeAddr))
                    if callee_func is None:
                        continue
                    calleeBlockSize = GetFuncBlockSize(callee_func, current_program)
                    # Count references to callee (match IDA's CodeRefsTo behavior)
                    refs_to_callee = ref_manager.getReferencesTo(flat_api.toAddr(calleeAddr))
                    ref_count = sum(1 for r in refs_to_callee if r.getReferenceType().isCall())
                    if (calleeBlockSize <= checkIfCallersCalleeNeedInlineCalleeSizeThreshold
                            and ref_count <= checkIfCallersCalleeNeedInlineCalleeRefedThreshold):
                        inlineList.append(calleeAddr)

        # If this function only has lib call, then current analyzed function should be inlined.
        if allLibcCall:
            if start not in inlineList:
                # Match IDA: use unfiltered block count for allLibcCall path
                from ghidra.program.model.block import BasicBlockModel
                from ghidra.util.task import TaskMonitor
                block_model = BasicBlockModel(current_program)
                monitor = TaskMonitor.DUMMY
                blocks = block_model.getCodeBlocksContaining(func.getBody(), monitor)
                block_count = len(list(blocks))
                if block_count < 20:
                    inlineList.append(start)

    # Write total inline number
    os.makedirs("./" + program + "/dump", exist_ok=True)
    fp = open("./" + program + "/dump/total_inline_number.txt", "w")
    fp.write(str(len(inlineList)))
    fp.close()
    return inlineList

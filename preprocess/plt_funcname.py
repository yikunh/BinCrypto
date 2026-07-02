"""
用于分析PLT段中的函数条目 - Ghidra版本
"""
import os


def _get_funcname_at(flat_api, current_program, addr):
    """Get the best function name at an address using multiple methods"""
    # Method 1: Function object
    func = current_program.getFunctionManager().getFunctionContaining(addr)
    if func:
        return func.getName()

    # Method 2: Primary symbol
    sym = current_program.getSymbolTable().getPrimarySymbol(addr)
    if sym:
        return sym.getName()

    # Method 3: Follow JMP -> GOT -> external symbol
    listing = current_program.getListing()
    ref_manager = current_program.getReferenceManager()
    ins = listing.getInstructionAt(addr)
    if ins:
        refs = ref_manager.getReferencesFrom(ins.getAddress())
        for ref in refs:
            to_addr = ref.getToAddress()
            # Check if reference goes to GOT
            memory = current_program.getMemory()
            got_block = memory.getBlock(to_addr)
            if got_block and (".got" in got_block.getName()):
                # Follow reference from GOT entry to external symbol
                got_refs = ref_manager.getReferencesFrom(to_addr)
                for got_ref in got_refs:
                    ext_addr = got_ref.getToAddress()
                    ext_sym = current_program.getSymbolTable().getPrimarySymbol(ext_addr)
                    if ext_sym:
                        return ext_sym.getName()
                # Try external function
                ext_func = current_program.getFunctionManager().getFunctionContaining(to_addr)
                if ext_func:
                    return ext_func.getName()
            elif to_addr.isExternalAddress():
                ext_sym = current_program.getSymbolTable().getPrimarySymbol(to_addr)
                if ext_sym:
                    return ext_sym.getName()

    return ""


def check_if_a_libc_plt_item(ea, text_start, text_end, flat_api, current_program):
    """Check if PLT entry is a library function (returns True=libc, False=internal)"""
    ref_manager = current_program.getReferenceManager()
    from_addr = flat_api.toAddr(ea)
    refs = ref_manager.getReferencesFrom(from_addr)

    for ref in refs:
        to_addr = ref.getToAddress()
        to_offset = to_addr.getOffset()

        if to_offset >= text_start and to_offset < text_end:
            func = current_program.getFunctionManager().getFunctionContaining(to_addr)
            if func:
                return False

        got_seg = current_program.getMemory().getBlock(".got")
        got_plt_seg = current_program.getMemory().getBlock(".got.plt")

        is_got = False
        if got_seg:
            if to_offset >= got_seg.getStart().getOffset() and to_offset < got_seg.getEnd().getOffset():
                is_got = True
        if not is_got and got_plt_seg:
            if to_offset >= got_plt_seg.getStart().getOffset() and to_offset < got_plt_seg.getEnd().getOffset():
                is_got = True

        if is_got:
            got_refs = ref_manager.getReferencesFrom(to_addr)
            for got_ref in got_refs:
                got_to = got_ref.getToAddress()
                got_to_offset = got_to.getOffset()
                if got_to_offset >= text_start and got_to_offset < text_end:
                    return False

    return True


def dump_plt_funcname(flat_api, program, binary_start_ea, text_start, text_end):
    current_program = flat_api.getCurrentProgram()
    memory = current_program.getMemory()
    listing = current_program.getListing()

    plt_seg = memory.getBlock(".plt")
    if plt_seg:
        plt_start = plt_seg.getStart().getOffset()
    else:
        print("No .plt section found")
        return

    plt_got_seg = memory.getBlock(".plt.got")
    if plt_got_seg:
        plt_end = plt_got_seg.getEnd().getOffset() + 1
    else:
        plt_end = plt_seg.getEnd().getOffset() + 1

    os.makedirs("./" + program + "/dump", exist_ok=True)

    fp = open("./" + program + "/dump/pltFunc.txt", "w")
    current_addr = flat_api.toAddr(plt_start)
    end_addr = flat_api.toAddr(plt_end)

    while current_addr < end_addr:
        funcname = _get_funcname_at(flat_api, current_program, current_addr)

        ins = listing.getInstructionAt(current_addr)
        ins_size = ins.getLength() if ins else 1

        if funcname:
            if not check_if_a_libc_plt_item(current_addr.getOffset(), text_start, text_end, flat_api, current_program):
                end_offset = current_addr.getOffset() + ins_size
                global_fp = open("./" + program + "/dump/funcUnitList.txt", "a")
                global_fp.write("start offset: " + str(current_addr.getOffset() - binary_start_ea) +
                               ", end offset: " + str(end_offset - binary_start_ea) +
                               ", should be inlined: " + str(1) +
                               ", name: " + funcname + "\n")
                global_fp.close()
            else:
                fp.write("address: " + str(current_addr.getOffset() - binary_start_ea) +
                        ", offset: " + str(current_addr.getOffset() - binary_start_ea) +
                        ", name: " + funcname + "\n")

        current_addr = current_addr.add(ins_size)

    fp.close()

    # Process .plt.sec
    plt_sec_seg = memory.getBlock(".plt.sec")
    if plt_sec_seg:
        plt_sec_start = plt_sec_seg.getStart().getOffset()
        plt_sec_end = plt_sec_seg.getEnd().getOffset() + 1

        current_addr = flat_api.toAddr(plt_sec_start)
        end_addr = flat_api.toAddr(plt_sec_end)

        while current_addr < end_addr:
            funcname = _get_funcname_at(flat_api, current_program, current_addr)

            ins = listing.getInstructionAt(current_addr)
            ins_size = ins.getLength() if ins else 1

            if funcname:
                if not check_if_a_libc_plt_item(current_addr.getOffset(), text_start, text_end, flat_api, current_program):
                    end_offset = current_addr.getOffset() + ins_size
                    global_fp = open("./" + program + "/dump/funcUnitList.txt", "a")
                    global_fp.write("start offset: " + str(current_addr.getOffset() - binary_start_ea) +
                                   ", end offset: " + str(end_offset - binary_start_ea) +
                                   ", should be inlined: " + str(1) +
                                   ", name: " + funcname + "\n")
                    global_fp.close()
                else:
                    fp = open("./" + program + "/dump/pltFunc.txt", "a")
                    fp.write("address: " + str(current_addr.getOffset() - binary_start_ea) +
                            ", offset: " + str(current_addr.getOffset() - binary_start_ea) +
                            ", name: " + funcname + "\n")
                    fp.close()

            current_addr = current_addr.add(ins_size)
    else:
        print("no .plt.sec found")

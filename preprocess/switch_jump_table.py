import os


def dump_switch_jump_table(flat_api, program_name, binary_start, rodata_start, rodata_end, text_start, text_end):

    current_program = flat_api.getCurrentProgram()
    memory = current_program.getMemory()
    listing = current_program.getListing()
    ref_manager = current_program.getReferenceManager()
    
    # 遍历.rodata段中的每个地址（使用Heads方式，与IDA的idautils.Heads对应）
    current_addr = flat_api.toAddr(rodata_start)
    end_addr = flat_api.toAddr(rodata_end)
    
    # 创建输出目录
    dump_dir = "./" + program_name + "/dump"
    
    while current_addr < end_addr:
        # 获取当前地址的数据大小（与IDA的get_item_size对应）
        data_item = listing.getDefinedDataAt(current_addr)
        if data_item:
            item_size = data_item.getLength()
        else:
            # 如果不是定义的数据，获取指令长度或默认为1
            ins = listing.getInstructionAt(current_addr)
            if ins:
                item_size = ins.getLength()
            else:
                item_size = 1
        
        is_ref_from_text = False
        switch_jump_addr = None
        jmp_table_func_name = ""
        
        # 检查是否有来自.text段的引用（与IDA的DataRefsTo对应）
        refs = ref_manager.getReferencesTo(current_addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            from_offset = from_addr.getOffset()
            if text_start <= from_offset < text_end:
                is_ref_from_text = True
                switch_jump_addr = from_addr
                # 获取引用地址所在的函数名
                func = current_program.getFunctionManager().getFunctionContaining(from_addr)
                if func:
                    jmp_table_func_name = func.getName()
                break
        
        # 检查是否满足跳转表条件
        if is_ref_from_text and item_size >= 4:
            # 获取前4字节数据（与IDA的get_dword对应）
            data = flat_api.getInt(current_addr)
            data_value = data & 0xffffffff
            
            # 如果数据不在.text段范围内，则加上当前地址（与IDA逻辑完全一致）
            if data_value < text_start or data_value >= text_end:
                data_value = (data_value + current_addr.getOffset()) & 0xffffffff
            
            # 检查是否是.text段地址
            if text_start <= data_value < text_end:
                # 验证是否是jmp指令（检查20条指令内是否有jmp，与IDA逻辑一致）
                threshold = 0
                check_addr = switch_jump_addr
                valid_jmp = False
                
                while threshold < 20 and check_addr:
                    ins = listing.getInstructionAt(check_addr)
                    if ins:
                        mnemonic = ins.getMnemonicString()
                        # 只检测"jmp"，不检测条件跳转（与IDA的print_insn_mnem == "jmp"一致）
                        if mnemonic == "jmp":
                            valid_jmp = True
                            break
                        # 移动到下一条指令（与IDA的next_head对应）
                        check_addr = check_addr.next()
                        threshold += 1
                    else:
                        break
                
                # 如果验证失败，跳过该项（与IDA逻辑一致）
                if not valid_jmp:
                    current_addr = current_addr.add(item_size)
                    continue
                
                # 获取目标地址所在的函数名
                target_func = current_program.getFunctionManager().getFunctionContaining(flat_api.toAddr(data_value))
                
                # 根据函数名输出到不同文件（与IDA逻辑完全一致）
                if target_func is None:
                    # 找不到该地址所属函数的情况
                    with open(dump_dir + "/other-switchBlock.txt", "a") as fp:
                        fp.write("location offset: " + str(switch_jump_addr.getOffset() - binary_start) + 
                                ", target offset: " + str(data_value - binary_start) + "\n")
                else:
                    if target_func.getName() == jmp_table_func_name:
                        with open(dump_dir + "/" + target_func.getName() + "-switchBlock.txt", "a") as fp:
                            fp.write("location offset: " + str(switch_jump_addr.getOffset() - binary_start) + 
                                    ", target offset: " + str(data_value - binary_start) + "\n")
                
                # 记录跳转表条目（与IDA逻辑一致）
                next_addr = current_addr.add(item_size)
                with open(dump_dir + "/switchTableEntry.txt", "a") as fp:
                    fp.write("switch jump table entry offset: " + str(current_addr.getOffset() - binary_start) + 
                            ", end offset: " + str(next_addr.getOffset() - binary_start) + "\n")
        
        # 移动到下一个地址
        current_addr = current_addr.add(item_size)
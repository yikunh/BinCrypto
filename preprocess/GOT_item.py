"""
记录每个GOT（Global Offset Table）条目的偏移地址、
指向的数据（通常是函数地址）
以及对应的函数名称 - Ghidra版本
"""
import os
    
def read_qword(flat_api, addr):
    value = 0
    try:
        for i in range(8):
            b = flat_api.getByte(addr.add(i)) & 0xFF   # 关键转换
            value |= (b << (i * 8))
        return value
    except:
        return 0

def dump_GOT_item(flat_api, program, got_start, got_end, binaryStartAddr, extern_start):
    
    if got_start == 0 or got_start >= got_end:
        return
    
    # print(extern_start + binaryStartAddr)
    # print('\n')

    # 确保输出目录存在
    os.makedirs("./" + program + "/dump", exist_ok=True)
    
    fp = open("./" + program + "/dump/binaryGOTItem.txt", "a")
    
    current_program = flat_api.getCurrentProgram()
    # 遍历GOT段中的每个地址（8字节对齐）
    current_addr = flat_api.toAddr(got_start)
    end_addr = flat_api.toAddr(got_end)
    
    while current_addr < end_addr:
        # 读取8字节数据（qword）
        data_value = read_qword(flat_api, current_addr)
        # data = flat_api.getLongLong(current_addr)
        # data_value = data & 0xffffffffffffffff
        
        # 获取函数名
        func = current_program.getFunctionManager().getFunctionContaining(flat_api.toAddr(data_value))
        funcname = func.getName() if func else "notFunc"
        
        # 忽略extern段外的地址
        # print(data_value)
        # Ghidra: extern_start is already absolute; IDA adds binaryStartAddr because IDA offsets
        if (data_value >= extern_start and extern_start != 0) or data_value < binaryStartAddr:
            data_value = 0
            fp.write("offset: " + str(current_addr.getOffset() - binaryStartAddr) +
                    ", data: " + str(data_value) +
                    ", name: " + funcname + "\n")
        else:
            # offset: GOT条目相对于二进制基址的偏移; data: GOT条目指向的地址相对于基址的偏移
            fp.write("offset: " + str(current_addr.getOffset() - binaryStartAddr) + 
                    ", data: " + str(data_value - binaryStartAddr) + 
                    ", name: " + funcname + "\n")
        
        # 移动到下一个地址（通常是8字节）
        current_addr = current_addr.add(8)
    
    fp.close()

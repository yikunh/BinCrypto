#@runtime PyGhidra
import pyghidra
import os
import sys
import re
import subprocess
import time
from os.path import join
from os.path import abspath
from os.path import dirname

CURR_PATH = dirname(abspath(__file__))


def _safe_name(funcname):
    """Replace characters that are invalid in Windows filenames"""
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


import switch_jump_table
import plt_funcname
import GOT_item
import need_inline
import func_offset
import func_arg
import func_ret_value
import offset_in_memoryOp
import out_block
import func_bb_offset
import bb_predcessor
import force_stop_block
import instruction_address_offset_list
import checkpoint_block
import loop_back_edge
# import dump_constant_loop

# 常量定义
FUNCATTR_START = 0
FUNCATTR_END = 8

# 全局变量
funcname = ""

# 主分析函数
def dump_all_func_bin(program, flat_api):
    global funcname
    
    current_program = flat_api.getCurrentProgram()
    memory = current_program.getMemory()
    
    # 获取基址
    image_base = current_program.getImageBase().getOffset()
    
    # 获取各个段时，减去基址得到相对偏移
    binary_start_ea = image_base  # 基址本身
    
    rodata_seg = memory.getBlock(".rodata")
    text_seg = memory.getBlock(".text")
    got_seg = memory.getBlock(".got")
    
    # 所有地址都减去 image_base，输出相对偏移
    rodata_start_ea = rodata_seg.getStart().getOffset() if rodata_seg else image_base
    rodata_end_ea = rodata_seg.getEnd().getOffset() if rodata_seg else (image_base - 1)
    text_start = text_seg.getStart().getOffset() if text_seg else image_base
    text_end = text_seg.getEnd().getOffset() if text_seg else (image_base - 1)
    got_start = got_seg.getStart().getOffset() if got_seg else image_base
    got_end = got_seg.getEnd().getOffset() if got_seg else (image_base - 1)
    
    got_plt_seg = memory.getBlock(".got.plt")
    got_plt_start = got_plt_seg.getStart().getOffset() if got_plt_seg else image_base
    got_plt_end = got_plt_seg.getEnd().getOffset()  if got_plt_seg else (image_base - 1)
    
    plt_sec_seg = memory.getBlock(".plt.sec")
    plt_sec_start = plt_sec_seg.getStart().getOffset() if plt_sec_seg else image_base
    plt_sec_end = plt_sec_seg.getEnd().getOffset()  if plt_sec_seg else (image_base - 1)
    
    plt_seg = memory.getBlock(".plt")
    plt_start = plt_seg.getStart().getOffset() if plt_seg else image_base
    
    plt_got_seg = memory.getBlock(".plt.got")
    if plt_got_seg:
        plt_end = plt_got_seg.getEnd().getOffset()
    else:
        plt_end = plt_seg.getEnd().getOffset()  if plt_seg else (image_base - 1)

    extern_seg = memory.getBlock("extern")
    if extern_seg:
        extern_start = extern_seg.getStart().getOffset()
    else:
        # Ghidra has no "extern" segment — compute from max real memory block boundary
        max_addr = image_base
        for block in memory.getBlocks():
            name = block.getName()
            # Skip special/external/overlay blocks
            if name.startswith("OVERLAY") or name.startswith("EXTERNAL") or name == "LOW_OTHER_MAPPING":
                continue
            block_end = block.getEnd().getOffset()
            if block_end > max_addr:
                max_addr = block_end
        extern_start = max_addr + 1
    
    
    data_seg = memory.getBlock(".data")
    data_start = data_seg.getStart().getOffset() if data_seg else image_base
    data_end = data_seg.getEnd().getOffset()  if data_seg else (image_base - 1)
    
    bss_seg = memory.getBlock(".bss")
    bss_start = bss_seg.getStart().getOffset() if bss_seg else image_base
    bss_end = bss_seg.getEnd().getOffset()  if bss_seg else (image_base - 1)
    
    data_rel_ro_seg = memory.getBlock(".data.rel.ro")
    data_rel_ro_start = data_rel_ro_seg.getStart().getOffset() if data_rel_ro_seg else image_base
    data_rel_ro_end = data_rel_ro_seg.getEnd().getOffset()  if data_rel_ro_seg else (image_base - 1)

    # 写入段边界信息（相对偏移）
    fp = open("./" + program + "/dump/binaryStartEndAddr.txt", "w")
    fp.write("binary start: " + str(0) + ", end: " + str(extern_start - image_base +1) + "\n")
    fp.write("data start: " + str(data_start - image_base) + ", end: " + str(data_end - image_base +1) + "\n")
    fp.write("bss start: " + str(bss_start - image_base) + ", end: " + str(bss_end - image_base +1) + "\n")
    fp.write("rodata start: " + str(rodata_start_ea - image_base) + ", end: " + str(rodata_end_ea - image_base +1) + "\n")
    fp.write("plt start: " + str(plt_start - image_base) + ", end: " + str(plt_end - image_base +1) + "\n")
    fp.write("text start: " + str(text_start - image_base) + ", end: " + str(text_end - image_base +1) + "\n")
    fp.write("got start: " + str(got_start - image_base) + ", end: " + str(got_end - image_base +1) + "\n")
    fp.write("gotplt start: " + str(got_plt_start - image_base) + ", end: " + str(got_plt_end - image_base +1) + "\n")
    fp.write("data_rel_ro start: " + str(data_rel_ro_start - image_base) + ", end: " + str(data_rel_ro_end - image_base +1) + "\n")
    fp.close()

    func_nargs_cache = {}
    var_arg_func_cache = []
    func_total_local_reg_cache = {}
    
    print("\t[+] Start dump all func's switch jump table.")
    ######################################
    # Find out switch jump table.
    ######################################
    switch_jump_table.dump_switch_jump_table(flat_api, program, binary_start_ea, rodata_start_ea, rodata_end_ea, text_start, text_end)
    
    print("\t[+] Start dump plt funcname")
    ######################################
    # plt call table dump                #
    ######################################
    plt_funcname.dump_plt_funcname(flat_api, program, binary_start_ea, text_start, text_end)
    
    print("\t[+] Start dump GOT.")
    ######################################
    # Dump GOT item.
    ######################################
    GOT_item.dump_GOT_item(flat_api, program, got_start, got_end, binary_start_ea, extern_start)
    GOT_item.dump_GOT_item(flat_api, program, got_plt_start, got_plt_end, binary_start_ea, extern_start)
    
    print("\t[+] Start dump inline function.")
    ######################################
    # Dump Inline function address.
    ######################################
    
    inlineList = []
    inlineList = need_inline.check_all_func_if_it_need_inline(flat_api, program, plt_start, plt_end, inlineList)
    
    # 获取所有函数（Ghidra方式）
    function_manager = current_program.getFunctionManager()
    functions = function_manager.getFunctions(True)
    
    for func in functions:
        funcname = func.getName()
        start = func.getEntryPoint().getOffset()
        end = func.getBody().getMaxAddress().getOffset()
        
        print("[*] Current analysis: ", funcname)
        
        # only analysis text function
        if start < text_start or start > text_end:
            print("\t[+] Not in text section")
            continue
        
        print("\t[+] Start dump func offset")
        func_offset.dump_func_offset(flat_api, program, funcname, start, end, inlineList)
        
        print("\t[+] Start dump func prototype")
        if start in func_nargs_cache:
            print(funcname)
            print("\t", func_nargs_cache[start][0])
            print("\t", func_nargs_cache[start][1])
            file = "./" + program + "/dump/" + _safe_name(funcname) + "-dumpPrototype.txt"
            if not os.path.exists(file):
                fp = open(file, "w")
                if start in var_arg_func_cache:
                    fp.write("Arg number: 99\n")
                else:
                    fp.write("Arg number: " + str(func_nargs_cache[start][0]) + "\n")
                fp.write("Reg arg number: " + str(func_nargs_cache[start][0]) + "\n")
                fp.write("Stack arg number: " + str(func_nargs_cache[start][1]) + "\n")
                fp.close()
        else:
            func_arg.dump_func_arg(flat_api, program, funcname, start, func_nargs_cache, var_arg_func_cache, func_total_local_reg_cache)
        
        print("\t[+] Start dump func ret value")
        ######################################
        # function ret prototype dump        #
        ######################################
        func_ret_value.dump_func_ret_value(flat_api, program, funcname, start)
        
        print("\t[+] Start dump offset in memoryOp")
        ######################################
        # dump offset in memoryOp instruction#
        ######################################
        offset_in_memoryOp.dump_offset_in_memoryOp(flat_api, program, funcname, start)
        
        print("\t[+] Start dump all block's out block address")
        ######################################
        # Find out block for all block.
        ######################################
        out_block.dump_find_out_block_for_all_block_in_func(flat_api, program, funcname, func, binary_start_ea)
        
        print("\t[+] Start dump function basic block offset")
        ######################################
        # Dump func basic block offset.
        ######################################
        func_bb_offset.dump_func_bb_offset(flat_api, program, funcname, func, binary_start_ea)
        
        print("\t[+] Start dump function basic block's predcessor's offset")
        ######################################
        # Dump func basic block' all preds' offset.
        ######################################
        bb_predcessor.dump_bb_predcessor(flat_api, program, funcname, func, binary_start_ea)

        print("\t[+] Start dump force stop block")
        ######################################
        # Find force stop block.
        ######################################
        force_stop_block.dump_force_stop_block(flat_api, program, func, binary_start_ea)

        print("\t[+] Start dump all instruction address offset.")
        ######################################
        # Dump all instruction address as a list.
        ######################################
        instruction_address_offset_list.dump_instruction_address_offset_list(flat_api, program, funcname, func, binary_start_ea)
        
        print("\t[+] Start dump checkpoint block.")
        ######################################
        # Dump check point basic block
        ######################################
        checkpoint_block.dump_checkpoint_block(flat_api, program, funcname, func, binary_start_ea)

        print("\t[+] Start dump loop back edge.")
        ######################################
        # Dump loop back edge in function
        ######################################
        loop_back_edge.dump_loop_back_edge(flat_api, program, funcname, func, binary_start_ea)
    
    return

if __name__ == "__main__":
    # Ghidra环境下获取参数的方式
    programname = sys.argv[1]
    binary_path = "./Binary"
    
    ghidra_headless = r""
    project_dir = join(CURR_PATH, "ghidra_projects")
    project_name = f"temp_project_{programname}"
    binary_file = join(binary_path, programname)
    
    # 清理旧目录
    p = subprocess.Popen('rd /s/q ' + programname, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.wait()

    p = subprocess.Popen('del result_log.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.wait()

    # E.g., mkdir curl-o1
    p = subprocess.Popen('md '  + programname, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.wait()

    # E.g., mkdir curl-o1/dump
    p = subprocess.Popen('md '  + programname + "\\dump", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.wait()

    # Ghidra分析命令
    # analyzeHeadless.bat <project_dir> <project_name> -import <binary> -postScript <script> <script_args>
    # cmd = f'"{ghidra_headless}" "{project_dir}" "{project_name}" -import "{binary_file}" -postScript "{GHIDRA_SCRIPT}" -scriptParam "{CURR_PATH}" -scriptParam "{programname}"'
    # print(cmd)

    ##############################################################
    # Do Ghidra analysis, and store the dump function binary result.
    ##############################################################
    start = time.time()
    
    # 启动Ghidra分析
    pyghidra.start(install_dir=r"")

    
    # 注意：在headless模式下，程序已经被导入，直接获取当前程序
    with pyghidra.open_program(binary_file) as flat_api: 
        dump_all_func_bin(programname, flat_api)
    # Do Ghidra analysis
    # p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # p.wait()
    
    end = time.time()
    fp = open("./log/" + programname + "_analysis_time.txt", "w")
    fp.write("analysis time: {:.2f}s.\n".format(end - start))
    fp.close()

    print("Finish ghidra parse")

    sys.exit(0)
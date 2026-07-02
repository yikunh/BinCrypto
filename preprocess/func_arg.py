"""
通过Ghidra函数签名识别函数的参数个数、
参数传递方式（寄存器/栈）以及判断是否为可变参数函数 - Ghidra版本
"""
import os
import re


def _safe_name(funcname):
    """Replace characters that are invalid in Windows filenames"""
    return re.sub(r'[<>:"/\\|?*]', '_', funcname)


def _is_vararg(func):
    """Check if function has variable arguments via calling convention string"""
    try:
        conv = func.getCallingConventionName()
        if conv and "varargs" in conv.lower():
            return True
    except Exception:
        pass
    return False


def dump_func_arg(flat_api, program, funcname, funcStartAddr, func_nargs_cache, var_arg_func_cache, func_total_local_reg_cache):
    current_program = flat_api.getCurrentProgram()
    function_manager = current_program.getFunctionManager()
    func = function_manager.getFunctionContaining(flat_api.toAddr(funcStartAddr))

    if not func:
        func_nargs_cache[funcStartAddr] = (0, 0)
        func_total_local_reg_cache[funcStartAddr] = []
        return

    # Count function parameters (exclude auto params like return storage)
    params = func.getParameters()
    nargs = len([p for p in params if not p.isAutoParameter()])

    is_vararg = _is_vararg(func)

    # x86-64 System V ABI: first 6 args in registers, rest on stack
    if is_vararg:
        var_arg_func_cache.append(funcStartAddr)

    stack_args = nargs - 6 if nargs > 6 else 0
    func_nargs_cache[funcStartAddr] = (nargs, stack_args)

    func_total_local_reg_cache[funcStartAddr] = []

    os.makedirs("./" + program + "/dump", exist_ok=True)
    fp = open("./" + program + "/dump/" + _safe_name(funcname) + "-dumpPrototype.txt", "w")
    if funcStartAddr in var_arg_func_cache:
        fp.write("Arg number: 99\n")
    else:
        fp.write("Arg number: " + str(nargs) + "\n")
    fp.write("Reg arg number: " + str(nargs) + "\n")
    fp.write("Stack arg number: " + str(stack_args) + "\n")
    fp.close()

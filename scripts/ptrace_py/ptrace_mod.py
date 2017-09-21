#!/usr/bin/env python3
"""
    expects following input:
    ./modify.py <path_to_config>
    the config may look like:
    {
        "binary": <path_to_binary>,
        "mods": {
            <filename>: [<addresses>]
        },
        "params": <params to test>,
        "exp_out": {
            "ret": <retval>,
            "stdout": <stdout>,
            "stderr": <stderr>
        },
        "fail_in": <stdin>,
    }
"""
import sys
import os
import json
import itertools
from tempfile import TemporaryFile
from pprint import PrettyPrinter
import capstone
from capstone import CS_ARCH_X86, CS_MODE_64
from bitstring import BitArray
from ptrace.debugger.child import createChild
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.tools import locateProgram


DIAS = capstone.Cs(CS_ARCH_X86, CS_MODE_64)
TMPDIR = "./tmpfiles/"
PP = PrettyPrinter()


def main(config):
    """
        receives arguments and checks for possible modifications
    """
    binary = os.path.abspath(config["binary"])
    fail_params = config["params"]
    _, mods = get_mods(config["mods"])
    succ_info = config["exp_out"]
    check_mods(binary, succ_info, fail_params, mods, config["fail_in"])
    return 0


def check_mods(binary, succ_info, fail_params, modifications, stdin):
    """
        checks which modification generates the same output
    """
    arguments = [locateProgram(binary)]
    arguments = arguments + fail_params.split()
    cnt = 0

    dbg = PtraceDebugger()
    out_lookup = {}
    mod_lookup = {}
    for i in range(len(modifications)):
        for mods in itertools.combinations(modifications, i+1):
            to_modify = []
            tmp_mods = list(mods)
            for entry in mods:
                fname, addr, op_len, ops = entry
                tmp_mods.remove(entry)
                if len(tmp_mods) != i:
                    continue
                for op in ops:
                    to_mod = [(fname, addr, op_len, op)]
                    if tmp_mods:
                        for j in range(max([len(x[3]) for x in tmp_mods])):
                            to_mod = [(fname, addr, op_len, op)]
                            for m_f, m_a, m_l, m_ops in tmp_mods:
                                if len(m_ops) > j:
                                    to_mod.append((m_f, m_a, m_l, m_ops[j]))
                                    to_modify.append(to_mod)
                                else:
                                    break
                    else:
                        to_modify.append(to_mod)
            for mod in to_modify:
                cnt += 1
                tmp_out = (TemporaryFile(dir="/dev/shm"), TemporaryFile(dir="/dev/shm"))
                pid = createChild(arguments, True, None,
                                  tmp_out[0].fileno(), tmp_out[1].fileno(),
                                  bytes(stdin, encoding="utf8"))
                process = dbg.addProcess(pid, True)
                out_lookup[process] = tmp_out
                mod_lookup[process] = mod
                for m_f, m_a, m_l, m_op in mod:
                    for m in process.readMappings():
                        if m.permissions.find("x") > -1:
                            if m.pathname == m_f:
                                process.writeBytes(m.start + int(m_a, 16), m_op[1])
                process.cont()

    for p in dbg.list:
        p.waitExit()
        out_lookup[p][0].seek(0)
        out_lookup[p][1].seek(0)
        tmp_out = out_lookup[p][0].read().decode("utf-8")
        tmp_err = out_lookup[p][1].read().decode("utf-8")
        out_lookup[p][0].close()
        out_lookup[p][1].close()
        if tmp_out == succ_info["stdout"] and tmp_err == succ_info["stderr"]:
            for entry in mod_lookup[p]:
                print("0x{}({}) @ {} in {}".format(entry[3][1].hex(), entry[3][0],
                                                   entry[1], entry[0]))
            print()
    print("Tried {} runs".format(cnt))


def get_mods(mod_dic):
    """
        Loads a dict in the format
        generates all possible modifications
        (<filename>, <addr>, (<opcode_name>, <len>, <bytes>))
    """
    ret = []
    files = list(mod_dic.keys())

    for e in mod_dic:
        path = e
        for addr in mod_dic[e]:
            tmp_len, tmp_mods = get_mods_from_addr(path, int(addr, 16))
            tmp_s = (path, addr, tmp_len, tmp_mods)
            ret.append(tmp_s)
    return files, ret


def get_mods_from_addr(file, addr):
    """
        returns a triple including address, instruction length and the possible mods
    """
    ret = []
    instr = get_instr_from_addr(file, addr)
    ret += get_possible_mods(instr)
    return len(instr), ret


def get_instr_from_addr(file, addr):
    """
        fetches a instruction from the given file
        returns it as bitarray
    """
    with open(file, "rb") as f:
        file_str = bytearray(f.read())
        instr = file_str[addr]
        # deal with 2 byte instructions:
        if instr == 0xf:
            instr = instr << 8
            instr = instr + file_str[addr + 1]
            instr = BitArray(hex=str(0x0000)) + BitArray(hex=str(hex(instr)))
        else:
            instr = BitArray(hex=str(hex(instr)))
    return instr


def get_possible_mods(opcode):
    """
        Checks for given opcode and possible bitflip instructions
        returns a list of tuples including ("opcode", "bytes")
    """
    results = []
    pos_flips = [opcode.bytes]
    for i in range(1, 9):
        tmp = opcode.copy()
        tmp[-i] = not tmp[-i]
        pos_flips.append(tmp.bytes)

    for e in pos_flips:
        code = b"" + e + b"\x00"
        if len(code) == 3:
            code += b'\x00\x00\x00'
        dias = [x for x in DIAS.disasm(code, 0x0)]
        if dias:
            inst = dias[0]
            results.append((inst.mnemonic, e))
    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("<path_to_config> needed")
        exit()
    with open(sys.argv[1]) as conffile:
        conf = json.load(conffile)
    main(conf)

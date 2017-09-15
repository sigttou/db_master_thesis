#!/usr/bin/env python3
"""
    expects following input:
    ./modify.py <path_to_binary> <succ_outfile> <mod_instr> <fail_params>
    mod_inst may look like that:
    {file} {address}
    the succ_outfile includes a json with
    {
        "ret": <retval>,
        "stdout": <stdout>,
        "stderr": <stderr>
    }
"""
import sys
import subprocess
import os
import shutil
import contextlib
import json
import itertools
from pprint import PrettyPrinter
import capstone
from capstone import CS_ARCH_X86, CS_MODE_64
from bitstring import BitArray
from parse import parse


DIAS = capstone.Cs(CS_ARCH_X86, CS_MODE_64)
TMPDIR = "./tmpfiles/"
PP = PrettyPrinter()


def main(args):
    """
        receives arguments and checks for possible modifications
    """
    binary = os.path.abspath(args[0])
    fail_params = args[3]
    files, mods = get_mods(args[2])
    with open(args[1]) as f:
        succ_info = json.load(f)
    check_mods(binary, succ_info, fail_params, files, mods)
    return 0


def check_mods(binary, succ_info, fail_params, files, modifications):
    """
        checks which modification generates the same output
    """
    libs = [e for e in files if e != binary]
    for f in files:
        shutil.copy(f, TMPDIR + os.path.basename(f))
        shutil.copymode(f, TMPDIR + os.path.basename(f))
    for i in range(len(modifications)):
        for mods in itertools.combinations(modifications, i+1):
            to_modify = []
            tmp_mods = list(mods)
            for entry in mods:
                fname, addr, op_len, ops = entry
                tmp_mods.remove(entry)
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
                        to_modify.append(to_mod)
            print()
            PP.pprint(list(to_modify))
            print()
    exit(0)
    # apply every possible modification 
    mods = []
    for entry in [m for m in modifications]:
        entry_mods = modifications[entry]
        for addr, op_len, mods in entry_mods:
            for mod in mods:
                ret_dict = {}
                ret_dict["stdout"] = ""
                ret_dict["stderr"] = ""
                ret_dict["ret"] = 0
                tempfile = TMP_LIB
                if entry == binary:
                    tempfile = TMP_EXEC
                modify_bin(entry, tempfile, addr, op_len, mod)
                try:
                    if entry == binary:
                        ret_dict["stdout"] = subprocess.check_output([tempfile]
                                                                     + fail_params.split()
                                                                    ).decode("utf8")
                    else:
                        env = os.environ
                        env["LD_PRELOAD"] = os.path.abspath(tempfile)
                        ret_dict["stdout"] = subprocess.check_output([binary]
                                                                     + fail_params.split(), env=env
                                                                    ).decode("utf8")
                except subprocess.CalledProcessError as e:
                    ret_dict["ret"] = e.returncode
                    ret_dict["stdout"] = e.stdout.decode("utf8")
                    ret_dict["stderr"] = e.stdout.decode("utf8")
                if ret_dict == succ_info:
                    print("Success for {} at {} in {}".format(mod[0], addr, entry))

                with contextlib.suppress(FileNotFoundError):
                    shutil.rmtree(LIB_FOLDER + "*")


def modify_bin(binfile, tmpfile, addr, op_len, mod):
    """
        modifies the given binary file and places it in the tmp
    """
    addr = int(addr, 16)
    instr = mod[1]
    with open(binfile, "rb") as f:
        content = bytearray(f.read())
    if op_len == 16:
        content[addr] = instr[0]
        content[addr+1] = instr[1]
    else:
        content[addr] = int(instr.hex(), 16)
    with open(tmpfile, "wb") as f:
        f.write(content)
    shutil.copymode(binfile, tmpfile)


def get_mods(file):
    """
        Loads a file in the format
        <addr> <file>
        generates all possible modifications
        returns a list containing:
        (<filename>, <addr>, (<opcode_name>, <len>, <bytes>))
    """
    ret = []
    files = set()
    with open(file) as f:
        entries = f.readlines()

    for e in entries:
        result = parse("{addr} {path}", e)
        path = result["path"]
        files.add(path)
        addr = result["addr"]
        tmp_len, tmp_mods = get_mods_from_addr(path, int(addr, 16))
        tmp_s = (path, addr, tmp_len, tmp_mods)
        ret.append(tmp_s)
    return list(files), ret


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
    if len(sys.argv) < 3:
        print("<binary> <addr> needed")
        exit()
    main(sys.argv[1:])

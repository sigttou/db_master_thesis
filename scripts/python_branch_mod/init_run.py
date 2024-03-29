#!/usr/bin/env python3
"""
    this module runs the tests
"""
import sys
import subprocess
import difflib
import itertools
import shutil
import pprint
import os
import contextlib
import capstone
from capstone import CS_ARCH_X86, CS_MODE_64
from bitstring import BitArray
from parse import parse


PIN_BIN = "/home/user/.local/bin/pin"
PIN_TOOL = "/home/user/MSC/db_master_thesis/pin/branch_logger/obj-intel64/branchlog.so"
SUCC_FILE = "success.out"
FAIL_FILE = "failure.out"
TMP_EXEC = "./temp.elf"
TMP_LIB = "./mylib.so.6"
DIAS = capstone.Cs(CS_ARCH_X86, CS_MODE_64)

PP = pprint.PrettyPrinter()


def main(args):
    """
        Main function
    """
    binary = args[0]
    if not binary.startswith("/"):
        binary = os.getcwd() + "/" + args[0]
    successful = args[1]
    failure = args[2]

    fnull = open(os.devnull, 'w')
    print("running " + binary + " with " + successful +
          " as arguments (using pintools to log branches)")
    subprocess.call([PIN_BIN, "-t", PIN_TOOL, "-o", SUCC_FILE, "--", binary]
                    + successful.split(), stdout=fnull)
    print("running " + binary + " with " + failure +
          " as arguments (using pintools to log branches)")
    subprocess.call([PIN_BIN, "-t", PIN_TOOL, "-o", FAIL_FILE, "--", binary]
                    + failure.split(), stdout=fnull)

    with open(SUCC_FILE, "r") as sf:
        with open(FAIL_FILE, "r") as ff:
            diff = difflib.ndiff(sf.readlines(), ff.readlines())

    branches = {}

    for l in diff:
        if l.startswith("+") or l.startswith("-"):
            result = parse("{sym} {addr} - [{instr} {target}] in {path} {branchtaken}", l)
            addr = result["addr"]
            path = result["path"]
            if not branches.get(path):
                branches[path] = {}
            if branches[path].get(addr):
                branches[path][addr]["cnt"] += 1
            else:
                branches[path][addr] = {"instr": result["instr"],
                                        "target": result["target"],
                                        "cnt": 1
                                       }

    succ_out = subprocess.check_output([binary] + successful.split())
    found = False
    if branches.get(binary):
        found = check_mods(branches[binary], binary, succ_out, failure)
        if not found:
            print("NO modifications worked inside the binary")
        else:
            print("Following modification worked:")
            PP.pprint(found)

    for lib in [x for x in branches if x != binary]:
        found = []
        if branches.get(lib):
            found = check_mods(branches[lib], lib, succ_out, failure, True, binary)

    with contextlib.suppress(FileNotFoundError):
        os.remove(TMP_EXEC)
    with contextlib.suppress(FileNotFoundError):
        os.remove(TMP_LIB)
    return 0


def get_instr_from_addr(addr, file):
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


def get_possible_op_modifications(opcode):
    """
        Uses capstone to check if it's a valid opcode
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

    print(results)
    return results

def modify_bin(instr, addr, to_modify):
    """
        changes the given binary
    """
    addr = int(addr, 16)
    opcode = get_instr_from_addr(addr, to_modify)
    get_possible_op_modifications(opcode)
    return
    new_op = OP_LOOKUP["instructions"].get(instr)
    if not new_op:
        print("UNKNOWN OPCODE {}".format(instr))

    PP.pprint(new_op["forms"])
    new_op = int(new_op["forms"]["encodings"]["opcode"]["byte"], 16)

    with open(to_modify, "rb") as f:
        file_str = bytearray(f.read())
    file_str[addr] = new_op
    with open(to_modify, "wb") as f:
        f.write(file_str)
    return


def check_mods(branches, binary, succ_out, failure, is_lib=False, executeable=""):
    """
        modifies binary
    """
    found = []
    mods = get_mods(branches)
    to_modify = TMP_EXEC
    if is_lib:
        to_modify = TMP_LIB
    print("FOUND: {} possible modifications in {}".format(len(mods), binary))
    if not mods:
        return found

    for mod in mods:
        shutil.copyfile(binary, to_modify)
        for e in mod:
            modify_bin(e[1], e[0], to_modify)
        shutil.copymode(binary, to_modify)
        try:
            if not is_lib:
                output = subprocess.check_output([to_modify] + failure.split())
            else:
                env = os.environ
                env["LD_PRELOAD"] = TMP_LIB
                output = subprocess.check_output([executeable] + failure.split(), env=env)
        except subprocess.CalledProcessError:
            output = ""
            print("CRASH: with {}".format(mod))

        if succ_out == output:
            print("SUCCESS: same output for: {}".format(mod))
            found = mod
            break
    return found

def get_mods(branches):
    """
        return modifications from branches
    """
    to_modify = []
    for b in branches:
        branch = branches[b]
        if branch["cnt"] == 2:
            to_modify += [(b, branch["instr"])]

    mods = []
    for i in range(1, len(to_modify) + 1):
        for e in list(itertools.combinations(to_modify, i)):
            mods += [list(e)]
    return mods


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No path given")
        exit()
    main(sys.argv[1:])

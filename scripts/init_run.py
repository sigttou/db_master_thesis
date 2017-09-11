#!/usr/bin/env python3
"""
    this module runs the tests
"""
import sys
import subprocess
import difflib
import itertools
import shutil
import os
from parse import parse

PIN_BIN = "/home/user/.local/bin/pin"
PIN_TOOL = "/home/user/MSC/db_master_thesis/pin/branch_logger/obj-intel64/branchlog.so"
SUCC_FILE = "success.out"
FAIL_FILE = "failure.out"
TMP_EXEC = "./temp.elf"

def main(args):
    """
        Main function
    """
    binary = args[0]
    successful = args[1]
    failure = args[2]
    print("running " + binary + " with " + successful + " as arguments")
    subprocess.call([PIN_BIN, "-t", PIN_TOOL, "-o", SUCC_FILE, "--", binary]
                    + successful.split())
    print("running " + binary + " with " + failure + " as arguments")
    subprocess.call([PIN_BIN, "-t", PIN_TOOL, "-o", FAIL_FILE, "--", binary]
                    + failure.split())

    with open(SUCC_FILE, "r") as sf:
        with open(FAIL_FILE, "r") as ff:
            diff = difflib.ndiff(sf.readlines(), ff.readlines())

    branches = {}

    for l in diff:
        if(binary in l) and (l.startswith("+") or l.startswith("-")):
            result = parse("{sym} {addr} - [{instr} {target}] in {path} {branchtaken}", l)
            if branches.get(result["addr"]):
                branches[result["addr"]]["cnt"] += 1
            else:
                branches[result["addr"]] = {"instr": result["instr"],
                                            "target": result["target"],
                                            "cnt": 1
                                           }
    to_modify = []
    for b in branches:
        branch = branches[b]
        if branch["cnt"] == 2:
            to_modify += [(b, branch["instr"])]

    mods = []
    for i in range(1, len(to_modify) + 1):
        for e in list(itertools.combinations(to_modify, i)):
            mods += [list(e)]

    for mod in mods:
        shutil.copyfile(binary, TMP_EXEC)
        for e in mod:
            print("modifying {} at {}".format(e[1], e[0]))
            modify_bin(e[1], e[0])
        shutil.copymode(binary, TMP_EXEC)
        subprocess.call([TMP_EXEC] + failure.split())

    os.remove(TMP_EXEC)
    return 0


def modify_bin(instr, addr):
    """
        changes the given binary
    """
    addr = int(addr, 16)
    if instr == "jnz":
        new_op = int("0x74", 16)
    elif instr == "jz":
        new_op = int("0x74", 16)
    else:
        print("UNKNOWN OPCODE {}".format(instr))
        exit(1)

    with open(TMP_EXEC, "rb") as f:
        file_str = bytearray(f.read())
    file_str[addr] = new_op
    with open(TMP_EXEC, "wb") as f:
        f.write(file_str)
    return

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No path given")
        exit()
    main(sys.argv[1:])

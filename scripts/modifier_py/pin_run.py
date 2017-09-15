#!/usr/bin/env python3
"""
    expects following input:
    ./pin_run.py <binary> <succ_params> <fail_params>
    if will generate following files:
        mod_instr.out
        succ.out
        fail.out
"""
import sys
import os
import subprocess
import difflib
import json
from parse import parse

SUCC_PINOUT = "succpin.out"
FAIL_PINOUT = "failpin.out"
SUCC_OUT = "succ.out"
MOD_FILE = "mod_instr.out"
PIN_BIN = "/home/user/.local/bin/pin"
PIN_TOOL = "/home/user/MSC/db_master_thesis/pin/branch_logger/obj-intel64/branchlog.so"

def main(args):
    """
        receives arguments and checks for possible modifications
    """
    binary = os.path.abspath(args[0])
    success_params = args[1]
    fail_params = args[2]
    pin_run(binary, success_params, PIN_TOOL, SUCC_PINOUT, SUCC_OUT)
    pin_run(binary, fail_params, PIN_TOOL, FAIL_PINOUT, os.devnull)
    gen_addrdiff_file(SUCC_PINOUT, FAIL_PINOUT, MOD_FILE)
    os.remove(SUCC_PINOUT)
    os.remove(FAIL_PINOUT)
    return 0


def pin_run(binary, parameters, pin_tool, pinoutfile, outfile):
    """
        calls the pintoll and logs its output to the given file
    """
    output = b""
    stderr = b""
    retval = 0
    try:
        output = subprocess.check_output([PIN_BIN, "-t", pin_tool, "-o", pinoutfile, "--", binary]
                                         + parameters.split())
    except subprocess.CalledProcessError as e:
        retval = e.returncode if e.returncode else 0
        stderr = e.stderr
        output = e.stdout
    if not output:
        output = b""
    ret_dict = {}
    ret_dict["ret"] = retval
    ret_dict["stdout"] = output.decode("utf8")
    ret_dict["stderr"] = stderr.decode("utf8") if stderr else ""
    with open(outfile, "w") as json_f:
        json.dump(ret_dict, json_f)

def gen_addrdiff_file(a_file, b_file, outfile):
    """
        generates an info file out of the differences between the files
    """
    with open(a_file, "r") as a:
        with open(b_file, "r") as b:
            diff = difflib.ndiff(a.readlines(), b.readlines())

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
    with open(outfile, "w") as f:
        for path in branches:
            branch = branches[path]
            for addr in branch:
                if branch[addr]["cnt"] > 1:
                    print("{} {}".format(addr, path), file=f)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("<binary> <succ_params> <fail_params>")
        exit()
    main(sys.argv[1:])

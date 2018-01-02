#!/usr/bin/env python3
"""
    generates binaries to given folder with all bit flips for given address
"""

import sys
from os.path import basename
from parse import parse

def main(args):
    """
        args[0] ... dir to place no binaries in
        args[1] ... log file to parse
    """
    with open(args[1], 'r') as f:
        for l in f.readlines():
            output = parse("{addr} - {file}", l)
            bin_args = [None] * 3
            bin_args[2] = output["addr"]
            bin_args[1] = output["file"]
            bin_args[0] = args[0]
            modify(bin_args)

def modify(args):
    """
        args[0] ... dir to be placed at
        args[1] ... binary to change
        args[2] ... addr to flip
    """
    addr = int(args[2], 16)
    file = args[1]
    outdir = args[0]
    with open(file, 'rb') as f:
        f_storage = bytearray(f.read())
        if addr > len(f_storage):
            return 1
    for index in range(0, 8):
        out = outdir + basename(file) + '_' + str(hex(addr)) + '_' + str(index)
        with open(out, 'wb') as f:
            tmp = f_storage[addr]
            f_storage[addr] ^= 1 << index
            f.write(f_storage)
            f_storage[addr] = tmp
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("./gen_mod.py directory log.file")
        exit()
    main(sys.argv[1:])

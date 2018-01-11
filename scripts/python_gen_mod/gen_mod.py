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
        args[2] ... for longer files lower line number limit
        args[3] ... for longer files upper line number limit
    """
    with open(args[1], 'r') as f:
        lines = f.readlines()

    lower_l = 0
    upper_l = None

    if len(args) == 4:
        lower_l = int(args[2])
        upper_l = int(args[3])
    for l in lines[lower_l:upper_l]:
        output = parse("{addr} - {file}", l)

        bin_args = [None, None]
        bin_args[0] = args[0]
        bin_args[1] = output["addr"]

        with open(output["file"], 'rb') as f:
            f_storage = bytearray(f.read())
        modify(bin_args, f_storage, basename(output["file"]))

def modify(args, f_storage, name):
    """
        args[0] ... dir to be placed at
        args[1] ... addr to flip
    """
    outdir = args[0]
    addr = int(args[1], 16)
    if addr > len(f_storage):
        return 1

    for index in range(0, 8):
        out = outdir + name + '_' + str(hex(addr)) + '_' + str(index)
        with open(out, 'wb') as f:
            tmp = f_storage[addr]
            f_storage[addr] ^= 1 << index
            f.write(f_storage)
            f_storage[addr] = tmp
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("./gen_mod.py directory log.file lower_line_number upper_line_number")
        exit()
    main(sys.argv[1:])

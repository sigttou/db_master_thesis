#!/usr/bin/env python3
"""
    this module creates a modified elf
"""
import sys

def main(args):
    """
        Main function
    """
    print(args)
    addr = int(args[1], 16)
    new_op = int(args[2], 16)

    with open(args[0], "rb") as f:
        file_str = bytearray(f.read())

    print(hex(file_str[addr]))
    file_str[addr] = new_op
    print(hex(file_str[addr]))

    with open(args[0], "wb") as f:
        f.write(file_str)

    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No path given")
        exit()
    main(sys.argv[1:])

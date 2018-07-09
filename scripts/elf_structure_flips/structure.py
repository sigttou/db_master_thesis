#!/usr/bin/env python3
import sys
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


def main(elfpath):
    ranges_to_print = []
    try:
        with open(elfpath, 'rb') as f:
            elf = ELFFile(f)
    except FileNotFoundError:
        print("Err: " + elfpath + " not found!")
        sys.exit(-1)
    except ELFError:
        print("Err: " + elfpath + " not a valid ELF")
        sys.exit(-1)

    header = elf.header

    ranges_to_print.append((0, header.e_ehsize))
    ranges_to_print.append((header.e_phoff, header.e_phoff + (header.e_phentsize * header.e_phnum)))
    ranges_to_print.append((header.e_shoff, header.e_shoff + (header.e_shentsize * header.e_shnum)))

    for r in ranges_to_print:
        for n in range(r[0], r[1]):
            print(str(hex(n)) + " - " + elfpath)
    return


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Illegal number of parameters")
        print("structure.py <path_to_elf>")
        sys.exit(-1)
    main(sys.argv[1])

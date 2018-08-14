#!/usr/bin/env python3
import sys
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


def main(elfpath, offset):
    try:
        with open(elfpath, 'rb') as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                sec_size = sec["sh_size"]
                sec_off = sec["sh_offset"]
                if(offset > sec_off):
                    if(offset < (sec_off + sec_size)):
                        print(sec.name)
                        return
    except FileNotFoundError:
        print("Err: " + elfpath + " not found!")
        sys.exit(-1)
    except ELFError:
        print("Err: " + elfpath + " not a valid ELF")
        sys.exit(-1)
    print("not found")
    return


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Illegal number of parameters")
        print("section_find.py <path_to_elf> <offset>")
        sys.exit(-1)
    main(sys.argv[1], int(sys.argv[2]))

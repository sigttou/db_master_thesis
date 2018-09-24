#!/usr/bin/env python3
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


def get_elf(elfpath):
    try:
        f = open(elfpath, 'rb')
        elf = ELFFile(f)
        return f, elf
    except FileNotFoundError:
        print("Err: " + elfpath + " not found!")
        sys.exit(-1)
    except ELFError:
        print("Err: " + elfpath + " not a valid ELF")
        sys.exit(-1)


def get_section_name(elf, offset):
    for sec in elf.iter_sections():
        sec_size = sec["sh_size"]
        sec_off = sec["sh_offset"]
        if(offset > sec_off):
            if(offset < (sec_off + sec_size)):
                return sec.name
    print("Err: no section found")
    sys.exit(-1)


def main(filename, offset):
    f, elf = get_elf(filename)
    section_name = get_section_name(elf, offset)
    print(section_name)
    section = elf.get_section_by_name(section_name)
    base_addr = section['sh_addr']
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for (address, size, mnemonic, op_str) in md.disasm_lite(section.data(), base_addr):
            print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))
    f.close()
    return


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Illegal number of parameters")
        print("./classify.py <elffile> <offset>")
        sys.exit(-1)
    main(sys.argv[1], int(sys.argv[2], 16))

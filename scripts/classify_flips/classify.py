#!/usr/bin/env python3
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from parse import parse
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


def get_disass(data, base_addr):
    disass = {}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for (address, size, mnemonic, op_str) in md.disasm_lite(bytes(data), base_addr):
        disass[address] = (mnemonic, op_str)
    return disass


def print_diff(dis_a, dis_b, offset):
    index_a = offset
    while(not dis_a.get(index_a)):
        index_a -= 1
    index_b = offset
    while(not dis_b.get(index_b)):
        index_b -= 1

    print_dis = False
    if(index_a != index_b):
        print("CONTEXT")
        print_dis = True
    elif(dis_a[index_a][0] != dis_b[index_b][0]):
        print("OPCODE")
    elif(dis_a[index_a][1] != dis_b[index_b][1]):
        print("PARAM")
    else:
        # this should never pop up:
        print("OTHER")
        print_dis = True

    if(print_dis):
        print("ORIG: 0x%x:\t%s\t%s" % (index_a, dis_a[index_a][0], dis_a[index_a][1]))
        print("DIFF: 0x%x:\t%s\t%s" % (index_b, dis_b[index_b][0], dis_b[index_b][1]))


def classify(filename, offset, bit):
    f, elf = get_elf(filename)
    section_name = get_section_name(elf, offset)
    section = elf.get_section_by_name(section_name)
    base_addr = section['sh_addr']
    data = bytearray(section.data())

    dis_a = get_disass(data, base_addr)
    data[offset - base_addr] ^= 1 << bit
    dis_b = get_disass(data, base_addr)

    print_diff(dis_a, dis_b, offset)

    f.close()
    return


def main(logfile):
    try:
        with open(logfile, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Err: " + logfile + " not found!")
        sys.exit(-1)
    for l in lines:
        entry = parse("SUCCESS: {file}_0x{offset}_{bit} - {}", l)
        if(entry):
            classify(entry["file"], int(entry["offset"], 16), int(entry["bit"]))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Illegal number of parameters")
        print("./classify.py <logfile>")
        sys.exit(-1)
    main(sys.argv[1])

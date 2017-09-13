#!/usr/bin/env python3
"""
    modifies a given binary on the given address
"""
import sys
import capstone
from capstone import CS_ARCH_X86, CS_MODE_64
from bitstring import BitArray


DIAS = capstone.Cs(CS_ARCH_X86, CS_MODE_64)


def main(args):
    """
        receives arguments and checks for possible modifications
    """
    file = args[0]
    addr = int(args[1], 16)
    print("Checking for modifications in {} at {}".format(file, addr))
    print(get_mods_from_addr(file, addr))
    return 0


def get_mods_from_addr(file, addr):
    """
        returns a triple including address, instruction length and the possible mods
    """
    instr = get_instr_from_addr(file, addr)
    mods = (hex(addr), len(instr), get_possible_mods(instr))
    return mods


def get_instr_from_addr(file, addr):
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

def get_possible_mods(opcode):
    """
        Checks for given opcode and possible bitflip instructions
        returns a list of tuples including ("opcode", "bytes")
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
    return results


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("<binary> <addr> needed")
        exit()
    main(sys.argv[1:])

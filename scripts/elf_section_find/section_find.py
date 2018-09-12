#!/usr/bin/env python3
import sys
from parse import parse
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


def get_section(elfpath, offset):
    try:
        with open(elfpath, 'rb') as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                sec_size = sec["sh_size"]
                sec_off = sec["sh_offset"]
                if(offset > sec_off):
                    if(offset < (sec_off + sec_size)):
                        return sec.name
    except FileNotFoundError:
        print("Err: " + elfpath + " not found!")
        sys.exit(-1)
    except ELFError:
        print("Err: " + elfpath + " not a valid ELF")
        sys.exit(-1)
    return "not found"


def main(log_file):
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Err: " + log_file + " not found!")
        sys.exit(-1)

    for l in lines:
        entry = parse("SUCCESS: {file}_0x{offset}_{} - {}", l)
        if(entry):
            print(entry["file"] + " " + get_section(entry["file"], int(entry["offset"], 16)))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Illegal number of parameters")
        print("section_find.py <logfile_from_chroot_script>")
        sys.exit(-1)
    main(sys.argv[1])

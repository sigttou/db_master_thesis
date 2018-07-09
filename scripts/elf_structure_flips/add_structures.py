#!/usr/bin/env python3
import sys
import parse
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


def get_ranges(elfpath):
    ranges = []
    try:
        with open(elfpath, 'rb') as f:
            elf = ELFFile(f)
    except FileNotFoundError:
        return []
    except ELFError:
        print("Err: " + elfpath + " not a valid ELF")
        sys.exit(-1)

    header = elf.header
    ranges.append((0, header.e_ehsize))
    ranges.append((header.e_phoff, header.e_phoff + (header.e_phentsize * header.e_phnum)))
    ranges.append((header.e_shoff, header.e_shoff + (header.e_shentsize * header.e_shnum)))

    return ranges


def main(filepath):
    try:
        with open(filepath, "r") as f:
            entries = f.readlines()
    except FileNotFoundError:
        print("Err: " + filepath + " not found!")
        sys.exit(-1)

    files = {}
    for e in entries:
        entry = parse.parse("{addr} - {file}", e)
        if not files.get(entry["file"]):
            files[entry["file"]] = []
        files[entry["file"]].append(entry["addr"])

    entries = []
    for f in files.keys():
        for r in get_ranges(f):
            for n in range(r[0], r[1]):
                files[f].append(str(hex(n)))
        for e in set(files[f]):
            entries.append(str(e) + " - " + f + "\n")

    with open(filepath, "w") as f:
        f.writelines(entries)

    return


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Illegal number of parameters")
        print("structure.py <instrumenter_outfile>")
        sys.exit(-1)
    main(sys.argv[1])

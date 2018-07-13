#!/usr/bin/env python3
import sys
import parse
import os
import subprocess


def main(succ_file, mods_folder):
    with open(succ_file, "r") as f:
        content = f.readlines()
    for l in [x.strip() for x in content]:
        entry = parse.parse("SUCCESS: {modfile} - {dest}", l)
        cmd = "./objdump_diff.sh " + os.path.join(mods_folder, entry["modfile"]) + " " + entry["dest"]
        outfile = entry["modfile"] + ".diff"
        with open(outfile, "w") as f:
            p = subprocess.Popen(cmd, shell=True, stdout=f)
        p.wait()
        if p.returncode:
            os.remove(outfile)
    return


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Illegal number of parameters")
        print("./diff_success.py <path_to_successfile> <path_to_mod_files>")
        sys.exit(-1)
    main(sys.argv[1], sys.argv[2])

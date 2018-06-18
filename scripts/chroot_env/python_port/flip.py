#!/usr/bin/env python3

import sys
import json
import os
import time
from executor import execute, chroot
import parse

CONFIG_KEYS = [
        "instrumenter_call",
        "instrumenter_outfile",
        "chroot_template",
        "tmp_chroot_folder",
        "folder_with_flips",
        "num_of_parallel_checks",
        "CR_exec_file",
        "CR_flip_folder",
        "CR_log_file",
        ]


def load_config(config_path):
    """
    Loads a flip config file and returns a dict containing the keys
    Checks if all needed keys are present
    """
    config = {}

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except IOError:
        print("Could not open config file!")
        sys.exit(-1)
    except json.JSONDecodeError:
        print("Config file is not valid json!")
        sys.exit(-1)

    if not set(CONFIG_KEYS) == set(config.keys()):
        print("Config entries do not match needed ones")
        sys.exit(-1)

    if config["num_of_parallel_checks"] <= 0:
        print("Num of parallel runs need to be larger than 0")
        sys.exit(-1)

    return config


def instrument(config):
    """
    Run given binary and report results
    """
    execute(config["instrumenter_call"], silent=True)

    return


def generate_flips(config):
    """
    Generates flips and returns "file_flipped" or None if finished
    """
    def modify(addr, flip_dir, toflip_bin, filename):
        """
        Taken from scripts/python_gen_mod/gen_mod.py
        """
        addr = int(addr, 16)
        if(addr > len(toflip_bin)):
            return
        for i in range(8):
            out = flip_dir + filename + "_" + str(hex(addr)) + "_" + str(i)
            try:
                with open(out, "wb") as f:
                    tmp = toflip_bin[addr]
                    toflip_bin[addr] ^= 1 << i
                    f.write(toflip_bin)
                    toflip_bin[addr] = tmp
            except OSError:
                print("Failed in writing modified binary")
                sys.exit(-1)

        return

    file_flipped = ""
    try:
        with open(config["instrumenter_outfile"], 'r') as f:
            entries = f.readlines()
    except FileNotFoundError:
        print("Flips file not found! Possible failed instrumenting!")
        sys.exit(-1)

    todel = []
    for e in entries:
        entry = parse.parse("{addr} - {file}", e)
        file_flipped = entry["file"] if not file_flipped else file_flipped
        if(not file_flipped == entry["file"]):
            break

        fs_stats = os.statvfs(config["folder_with_flips"])
        blocks_needed = int((8 * os.path.getsize(entry["file"])) / fs_stats.f_bsize) + 1
        if(blocks_needed > fs_stats.f_bavail):
            break

        with open(entry["file"], "rb") as f:
            bin_content = bytearray(f.read())
        modify(entry["addr"], config["folder_with_flips"], bin_content, os.path.basename(entry["file"]))
        todel.append(e)

    entries = [e for e in entries if e not in todel]

    with open(config["instrumenter_outfile"], 'w') as f:
        f.writelines(entries)

    return file_flipped


def prepare_chroots(config):
    """
    Copies template chroot to some tmp folder and splits up flips to be tested by each chroot worker
    """
    try:
        num_of_flips = len([f for f in os.listdir(config["folder_with_flips"]) if
                            os.path.isfile(os.path.join(config["folder_with_flips"], f))])
        flips_per_worker = int((num_of_flips + config["num_of_parallel_checks"] - 1) /
                               config["num_of_parallel_checks"])
    except FileNotFoundError:
        print("Directory " + config["folder_with_flips"] + " with flips does not exist")
        sys.exit(-1)

    for i in range(config["num_of_parallel_checks"]):
        sub_flip_folder = os.path.join(config["folder_with_flips"], str(i))
        sub_chroot = os.path.join(config["tmp_chroot_folder"], str(i))
        sub_cr_flip_folder = sub_chroot + config["CR_flip_folder"]

        os.makedirs(sub_flip_folder, exist_ok=True)
        flips = [os.path.join(config["folder_with_flips"], f) for f in
                 os.listdir(config["folder_with_flips"]) if os.path.isfile(os.path.join(
                                                                           config["folder_with_flips"], f))]
        flips = flips[:flips_per_worker]
        if not flips:
            print("No flips left to move! - Run: " + str(i))
            break
        os.system("mv " + " ".join(flips) + " " + sub_flip_folder)

        if not os.path.isdir(sub_chroot):
            os.system("cp -R " + config["chroot_template"] + " " + sub_chroot)
        os.system("cp " + config["CR_exec_file"] + " " + sub_chroot + "/")

        if not os.path.isdir(sub_cr_flip_folder):
            os.makedirs(sub_cr_flip_folder, exist_ok=True)
            os.system("mount --bind " + sub_flip_folder + " " + sub_cr_flip_folder)

    return


def start_workers(config, file_flipped):
    """
    Creates a subprocess for each chroot to run the given commandfile
    """
    workers = []
    for i in range(config["num_of_parallel_checks"]):
        sub_chroot = os.path.join(config["tmp_chroot_folder"], str(i))
        command = "./" + os.path.basename(config["CR_exec_file"]) + " "
        command += config["CR_flip_folder"] + " " + file_flipped + " " + config["CR_log_file"]

        cmd = chroot.ChangeRootCommand(chroot=sub_chroot, command=[command], async=True, silent=True)
        cmd.start()
        workers.append(cmd)

    return workers


def check_results(config, logfile):
    """
    Checks all chroots for successfull bitflips
    """
    for i in range(config["num_of_parallel_checks"]):
        sub_log_file = os.path.join(config["tmp_chroot_folder"], str(i)) + config["CR_log_file"]
        try:
            f = open(sub_log_file)
            print(f.read(), file=open(logfile, "wa"))
        except FileNotFoundError:
            continue

    return


def clean_chroots(config):
    """
    Umounts and deletes folders in chroots after successfull runs
    """
    for i in range(config["num_of_parallel_checks"]):
        sub_chroot = os.path.join(config["tmp_chroot_folder"], str(i))
        sub_cr_flip_folder = sub_chroot + config["CR_flip_folder"]

        if os.path.isdir(sub_cr_flip_folder):
            os.system("umount " + sub_cr_flip_folder)
            os.system("rmdir " + sub_cr_flip_folder)
        if os.path.isdir(sub_chroot):
            os.system("rm -rf sub_chroot")

    return


def main(config_path):
    config = load_config(config_path)
    logfile = time.strftime("%Y%m%d-%H%M%S") + "-run_test"
    print("Successfully loaded config")
    instrument(config)
    print("Instrumented binary")

    while(True):
        file_flipped = generate_flips(config)
        if(not file_flipped):
            break
        print("Flips generated for " + file_flipped)
        prepare_chroots(config)
        print("Successfully prepared chroots")

        workers = start_workers(config, file_flipped)
        print("Started workers, waiting for them")
        for w in workers:
            w.wait()

        check_results(config, logfile)
        print("Checking done, cleaning up")
        clean_chroots(config)

    print("DONE - check " + logfile + " for results")

    return 0


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Illegal number of parameters")
        print("./flips.py <config>")
        sys.exit(-1)
    main(sys.argv[1])

#!/usr/bin/env python3

import sys
import json
import os
from executor import chroot

CONFIG_KEYS = [
        "chroot_template",
        "tmp_chroot_folder",
        "folder_with_flips",
        "file_flipped",
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
        sys.exit(-2)
    except json.JSONDecodeError:
        print("Config file is not valid json!")
        sys.exit(-3)

    if not set(CONFIG_KEYS) == set(config.keys()):
        print("Config entries do not match needed ones")
        sys.exit(-4)

    return config


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
        sys.exit(-5)

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


def start_workers(config):
    """
    Creates a subprocess for each chroot to run the given commandfile
    """
    workers = []
    for i in range(config["num_of_parallel_checks"]):
        sub_chroot = os.path.join(config["tmp_chroot_folder"], str(i))
        command = "./" + os.path.basename(config["CR_exec_file"]) + " "
        command += config["CR_flip_folder"] + " " + config["file_flipped"] + " " + config["CR_log_file"]

        cmd = chroot.ChangeRootCommand(chroot=sub_chroot, command=[command], async=True, silent=True)
        cmd.start()
        workers.append(cmd)

    return workers


def check_results(config):
    """
    Checks all chroots for successfull bitflips
    """
    for i in range(config["num_of_parallel_checks"]):
        sub_log_file = os.path.join(config["tmp_chroot_folder"], str(i)) + config["CR_log_file"]
        try:
            f = open(sub_log_file)
            print("OK: Success in " + sub_log_file)
            print(f.read())
        except FileNotFoundError:
            print("ERR: No success in " + sub_log_file)

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
    print("Successfully loaded config")
    prepare_chroots(config)
    print("Successfully prepared chroots")

    workers = start_workers(config)
    print("Started workers, waiting for them")
    for w in workers:
        w.wait()

    check_results(config)
    print("Checking done, cleaning up")
    clean_chroots(config)
    print("DONE")

    return 0


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Illegal number of parameters")
        print("./flips.py <config>")
        sys.exit(-1)
    main(sys.argv[1])

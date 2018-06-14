#!/usr/bin/env python3

import sys
import json


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
    return


def main(config_path):
    config = load_config(config_path)
    print("Successfully loaded config")
    prepare_chroots(config)
    print("Successfully prepared chroots")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Illegal number of parameters")
        print("./flips.py <config>")
        sys.exit(-1)
    main(sys.argv[1])

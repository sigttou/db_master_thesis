#!/usr/bin/env pypy

import sys
import angr
import simuvex
import pprint

INSTRUCTIONS = ["JNE", "JE", "LOOP"]

def main(proj):
    """
        Initializes the project
    """
    pp = pprint.PrettyPrinter(indent=2)
    instructions = []
    state = proj.factory.entry_state()
    state.inspect.b('instruction',
                    when=simuvex.BP_BEFORE,
                    action=lambda x: check_ins(x, instructions))

    while True:
        successor = state.step()
        if len(successor.successors) < 1:
            break
        state = successor.successors[0]

    pp.pprint(instructions)

def check_ins(state, instructions):
    """
        Checks for flipable instructions
    """
    addr = state.ip.args[0]
    ins = state.project.factory.block(addr).capstone.insns[0].insn.mnemonic.upper()
    if ins in INSTRUCTIONS:
        instructions += [(hex(addr), ins)]


if __name__ == "__main__":
    main(angr.Project(sys.argv[1], auto_load_libs=False))

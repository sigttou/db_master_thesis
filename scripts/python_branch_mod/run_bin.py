#!/usr/bin/env python3
"""
    This module runs binaries
"""

import sys
import os
from ctypes import CDLL, byref, c_wchar_p


def main(argv):
    """
        main function.
    """
    print(argv)
    c = CDLL("libc.so.6")
    fd = open(argv[0], "r")
    print(c.fexecve(fd.fileno(), c_wchar_p(sys.executable), c_wchar_p(1)))
    return 0


if __name__ == "__main__":
    main(sys.argv[1:])

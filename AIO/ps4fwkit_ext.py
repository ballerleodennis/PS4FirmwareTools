#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ps4fwkit_ext.py - Frontend fuer die Erweiterungsmodule
======================================================
  ps4fwkit_ext.py fs  <aktion> ...   -> ps4fwkit_fs
  ps4fwkit_ext.py elf <aktion> ...   -> ps4fwkit_elf
  ps4fwkit_ext.py auto <image>       -> Dateisystem erkennen und passend behandeln
"""

import sys
import ps4fwkit_fs
import ps4fwkit_elf

USAGE = __doc__


def main():
    if len(sys.argv) < 3:
        print(USAGE)
        return 1
    mod = sys.argv[1].lower()
    rest = sys.argv[2:]
    if mod == "fs":
        sys.argv = ["ps4fwkit_fs"] + rest
        return ps4fwkit_fs.main()
    if mod == "elf":
        sys.argv = ["ps4fwkit_elf"] + rest
        return ps4fwkit_elf.main()
    if mod == "auto":
        img = rest[0]
        fs = ps4fwkit_fs.open_fs(img)
        fs.info()
        print()
        if hasattr(fs, "walk"):
            for p, e in list(fs.walk())[:40]:
                size = e["size"] if isinstance(e, dict) else 0
                print("%10d  %s" % (size, p))
        fs.close()
        return 0
    print(USAGE)
    return 1


if __name__ == "__main__":
    sys.exit(main())
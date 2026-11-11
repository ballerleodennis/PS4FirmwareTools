#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ps4fwkit_elf.py - ELF64 / SELF Analyse fuer PS4-Firmware
========================================================
  * header   : ELF- bzw. SELF-Header dekodieren
  * sections : Section-Tabelle mit Namen auflisten
  * segments : Program-Header / PT_LOAD auflisten
  * split    : Segmente als Dateien herausschreiben
  * imports  : dynamische Symbole (Importe) listen
  * carve    : ELF-Magics in Rohdaten finden und bewerten

SELF wird als ELF-Wrapper behandelt: die Nutzlast ist ein eingebettetes ELF,
das bei (self_filesize - elf_filesize) beginnt. Entschluesselt wird nicht,
das erledigt die Konsole bzw. ps4-cfw-toolkit.
"""

import argparse
import struct
import sys
from pathlib import Path

ELF_MAGIC = b"\x7FELF"
SELF_MAGIC = b"\x54\x14\xF5\xEE"
SELF_MAGIC_BE = b"\xEE\xF5\x14\x54"

PT_LOAD = 1
PT_DYNAMIC = 2
PT_SCE_RELA = 0x60000000

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11

STT_FUNC = 2
STT_OBJECT = 1


def die(m):
    print("[!] " + m, file=sys.stderr)
    sys.exit(1)


def ok(m):
    print("[+] " + m)


def human(n):
    for u in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024 or u == "GiB":
            return ("%d %s" % (n, u)) if u == "B" else ("%.2f %s" % (n, u))
        n /= 1024.0


def load(path):
    return bytearray(Path(path).read_bytes())


def find_elf_base(data):
    """Liefert (elf_offset, self_info) - bei reinem ELF ist offset 0."""
    if bytes(data[:4]) == ELF_MAGIC:
        return 0, None
    if bytes(data[:4]) in (SELF_MAGIC, SELF_MAGIC_BE):
        ver, = struct.unpack_from("<I", data, 0x04)
        flags, typ = struct.unpack_from("<HH", data, 0x08)
        meta_off, = struct.unpack_from("<I", data, 0x0C)
        hlen, = struct.unpack_from("<Q", data, 0x10)
        elfsz, = struct.unpack_from("<Q", data, 0x18)
        selfsz, = struct.unpack_from("<Q", data, 0x20)
        base = selfsz - elfsz if elfsz and selfsz >= elfsz else hlen
        if bytes(data[base:base + 4]) != ELF_MAGIC:
            for off in range(0, min(len(data), 0x100000), 4):
                if bytes(data[off:off + 4]) == ELF_MAGIC:
                    base = off
                    break
        return base, dict(version=ver, flags=flags, type=typ, meta_off=meta_off,
                          header_len=hlen, elf_size=elfsz, self_size=selfsz)
    die("weder ELF noch SELF (Magic %s)" % bytes(data[:4]).hex(" "))


class ELF:
    def __init__(self, path):
        self.data = load(path)
        self.base, self.selfinfo = find_elf_base(self.data)
        h = self.base
        if len(self.data) < h + 0x40:
            die("ELF-Header abgeschnitten")
        (self.e_type, self.e_machine) = struct.unpack_from("<HH", self.data, h + 0x10)
        self.e_entry, = struct.unpack_from("<Q", self.data, h + 0x18)
        self.e_phoff, = struct.unpack_from("<Q", self.data, h + 0x20)
        self.e_shoff, = struct.unpack_from("<Q", self.data, h + 0x28)
        self.e_flags, = struct.unpack_from("<I", self.data, h + 0x30)
        self.e_ehsize, = struct.unpack_from("<H", self.data, h + 0x34)
        self.e_phentsize, = struct.unpack_from("<H", self.data, h + 0x36)
        self.e_phnum, = struct.unpack_from("<H", self.data, h + 0x38)
        self.e_shentsize, = struct.unpack_from("<H", self.data, h + 0x3A)
        self.e_shnum, = struct.unpack_from("<H", self.data, h + 0x3C)
        self.e_shstrndx, = struct.unpack_from("<H", self.data, h + 0x3E)
        if self.e_phentsize not in (0, 0x38):
            die("phentsize 0x%X unerwartet" % self.e_phentsize)
        if self.e_shentsize not in (0, 0x40):
            die("shentsize 0x%X unerwartet" % self.e_shentsize)

    def phdrs(self):
        for i in range(min(self.e_phnum, 512)):
            o = self.base + self.e_phoff + i * 0x38
            if o + 0x38 > len(self.data):
                return
            p_type, p_flags, p_off, p_vaddr, p_paddr, p_fsz, p_msz, p_al = \
                struct.unpack_from("<IIQQQQQQ", self.data, o)
            yield dict(index=i, type=p_type, flags=p_flags, offset=p_off,
                       vaddr=p_vaddr, paddr=p_paddr, filesz=p_fsz,
                       memsz=p_msz, align=p_al)

    def shdrs(self):
        if not self.e_shoff:
            return
        for i in range(min(self.e_shnum, 4096)):
            o = self.base + self.e_shoff + i * 0x40
            if o + 0x40 > len(self.data):
                return
            vals = struct.unpack_from("<IIQQQQIIQQ", self.data, o)
            yield dict(index=i, name_off=vals[0], type=vals[1], flags=vals[2],
                       addr=vals[3], offset=vals[4], size=vals[5],
                       link=vals[6], info=vals[7], align=vals[8], entsize=vals[9])

    def shstrtab(self):
        for s in self.shdrs() or []:
            if s["index"] == self.e_shstrndx:
                return bytes(self.data[s["offset"]:s["offset"] + s["size"]])
        return b""

    def sh_name(self, off, strtab):
        end = strtab.find(b"\0", off)
        return strtab[off:end if end > 0 else len(strtab)].decode("latin-1", "replace")

    def section_name(self, s, strtab):
        return self.sh_name(s["name_off"], strtab) if strtab else "?"

    def imports(self):
        strtab = b""
        for s in self.shdrs() or []:
            if s["type"] == SHT_STRTAB and s["index"] != self.e_shstrndx:
                strtab = bytes(self.data[s["offset"]:s["offset"] + s["size"]])
                break
        for s in self.shdrs() or []:
            if s["type"] != SHT_DYNSYM or not s["entsize"]:
                continue
            n = s["size"] // s["entsize"]
            for i in range(n):
                o = s["offset"] + i * s["entsize"]
                if o + 24 > len(self.data):
                    break
                name_off, info, other, shndx, value, size = \
                    struct.unpack_from("<IBBHQQ", self.data, o)
                st_type = info & 0xF
                bind = info >> 4
                if shndx != 0 or st_type not in (STT_FUNC, STT_OBJECT):
                    continue
                if bind not in (1, 2):
                    continue
                print("0x%08X  %-40s %s" % (value, self.sh_name(name_off, strtab) or "?",
                                            "FUNC" if st_type == STT_FUNC else "OBJECT"))


def cmd_header(a):
    e = ELF(a.file)
    print("ELF-Basis        : 0x%X" % e.base)
    if e.selfinfo:
        s = e.selfinfo
        print("SELF-Wrapper     : version=0x%X flags=0x%04X type=0x%04X meta=0x%X hlen=%d"
              % (s["version"], s["flags"], s["type"], s["meta_off"], s["header_len"]))
        print("ELF-Groesse      : %s   SELF-Groesse: %s"
              % (human(s["elf_size"]), human(s["self_size"])))
    print("e_type           : 0x%04X   e_machine: 0x%04X   e_flags: 0x%X"
          % (e.e_type, e.e_machine, e.e_flags))
    print("e_entry          : 0x%X" % e.e_entry)
    print("Program-Header   : %d x 0x%X @ 0x%X" % (e.e_phnum, e.e_phentsize, e.e_phoff))
    print("Section-Header   : %d x 0x%X @ 0x%X" % (e.e_shnum, e.e_shentsize, e.e_shoff))
    print()
    print("Hinweis: e_machine 0x3E = x86-64 (GameOS), 0xB7 = AArch64 (EAP).")


def cmd_segments(a):
    e = ELF(a.file)
    print("%-3s %-12s %-6s %-12s %-12s %-12s %s"
          % ("#", "Typ", "Flags", "Offset", "VAddr", "Filesz", "Memsz"))
    for p in e.phdrs():
        t = {PT_LOAD: "LOAD", PT_DYNAMIC: "DYNAMIC",
             PT_SCE_RELA: "SCE_RELA"}.get(p["type"], "0x%X" % p["type"])
        print("%-3d %-12s %-6s 0x%-10X 0x%-10X %-12s %s"
              % (p["index"], t, "R%c%c" % ("W" if p["flags"] & 2 else "-",
                                           "X" if p["flags"] & 1 else "-"),
                 p["offset"], p["vaddr"], human(p["filesz"]), human(p["memsz"])))


def cmd_sections(a):
    e = ELF(a.file)
    strtab = e.shstrtab()
    print("%-4s %-30s %-10s %-12s %-12s %s"
          % ("#", "Name", "Typ", "Addr", "Offset", "Size"))
    for s in e.shdrs() or []:
        print("%-4d %-30s 0x%-8X 0x%-10X 0x%-10X %s"
              % (s["index"], e.section_name(s, strtab), s["type"], s["addr"],
                 s["offset"], human(s["size"])))


def cmd_split(a):
    e = ELF(a.file)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    n = 0
    for p in e.phdrs():
        if a.load_only and p["type"] != PT_LOAD:
            continue
        if p["filesz"] == 0:
            continue
        data = bytes(e.data[p["offset"]:p["offset"] + p["filesz"]])
        if not data:
            continue
        dst = out / ("ph%02d_type%X_vaddr%016X.bin" % (p["index"], p["type"], p["vaddr"]))
        dst.write_bytes(data)
        ok("%s  (%s)" % (dst.name, human(len(data))))
        n += 1
    ok("%d Segmente -> %s" % (n, out))


def cmd_imports(a):
    ELF(a.file).imports()


def cmd_carve(a):
    data = Path(a.file).read_bytes()
    hits = 0
    start = 0
    while True:
        i = data.find(ELF_MAGIC, start)
        if i < 0:
            break
        start = i + 1
        if i + 0x40 > len(data):
            continue
        if data[i + 4] != 2 or data[i + 5] != 1:
            continue
        e_type, e_machine = struct.unpack_from("<HH", data, i + 0x10)
        if e_machine not in (0x3E, 0xB7):
            continue
        phoff, = struct.unpack_from("<Q", data, i + 0x20)
        phnum, = struct.unpack_from("<H", data, i + 0x38)
        print("0x%08X  ELF type=0x%X machine=0x%X phnum=%d phoff=0x%X"
              % (i, e_type, e_machine, phnum, phoff))
        hits += 1
    ok("%d eingebettete ELFs (x86-64 / AArch64)" % hits)


def main():
    ap = argparse.ArgumentParser(prog="ps4fwkit_elf",
                                 description="ELF64/SELF-Analyse fuer PS4-Firmware")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("header", cmd_header), ("segments", cmd_segments),
                     ("sections", cmd_sections), ("imports", cmd_imports),
                     ("carve", cmd_carve)):
        p = sub.add_parser(name)
        p.add_argument("file")
        p.set_defaults(func=fn)
    p = sub.add_parser("split")
    p.add_argument("file")
    p.add_argument("-o", "--out", default="elf_out")
    p.add_argument("--load-only", action="store_true")
    p.set_defaults(func=cmd_split)
    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
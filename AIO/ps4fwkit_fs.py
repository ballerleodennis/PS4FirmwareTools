#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ps4fwkit_fs.py - Read-only Dateisystem-Parser fuer PS4-Firmware-Images
=====================================================================
Unterstuetzt:
  * UFS2  (Orbis OS - coreos.img, system_fs_image.img nach Entschluesselung)
  * FAT12 / FAT16 / FAT32 / TEXFAT (Sony-Variante, FAT-kompatibel)

Aktionen: list, tree, cat, extract, stat, info
Nur lesend. Nichts wird im Image veraendert.

UFS2-Felder werden ueber die stabilen Offsets des FreeBSD-`struct fs`
gelesen (fs_bsize/f_fsize/f_frag/f_nindir/f_inopb/f_ipg/f_fpg/f_iblkno/
fsbtodb), Inode-Groesse ist 256 Byte, Root-Inode ist 2.
"""

import argparse
import os
import stat as statmod
import struct
import sys
from pathlib import Path

SBLOCK_UFS2 = 65536
FS_MAGIC_OFF = 0x55C
UFS2_MAGIC = 0x19540119
UFS_ROOTINO = 2
DINODE_SIZE = 256
DEV_BSIZE = 512

ATTR_LFN = 0x0F
ATTR_VOLUME = 0x08
ATTR_DIR = 0x10
ATTR_ARCHIVE = 0x20


def die(m):
    print("[!] " + m, file=sys.stderr)
    sys.exit(1)


def ok(m):
    print("[+] " + m)


def human(n):
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or u == "TiB":
            return ("%d %s" % (n, u)) if u == "B" else ("%.2f %s" % (n, u))
        n /= 1024.0


def safe_name(name, used):
    name = name.replace("\\", "_").replace("/", "_").replace(":", "_")
    name = name.replace("\0", "").strip() or "_"
    if name in (".", ".."):
        name = "_" + name
    base, ext = os.path.splitext(name)
    i = 1
    while name in used:
        name = "%s~%d%s" % (base, i, ext)
        i += 1
    used.add(name)
    return name


# ============================================================== UFS2
class UFS2:
    def __init__(self, path):
        self.path = Path(path)
        self.f = open(self.path, "rb")
        self.fsize_img = self.path.stat().st_size
        self._read_super()

    def close(self):
        self.f.close()

    def _read_super(self):
        self.f.seek(SBLOCK_UFS2)
        sb = self.f.read(0x800)
        if len(sb) < 0x800:
            die("Superblock bei 0x10000 nicht lesbar")
        if struct.unpack_from("<I", sb, FS_MAGIC_OFF)[0] != UFS2_MAGIC:
            die("kein UFS2-Magic bei 0x1055C (Datei ist kein UFS2-Image)")

        def i32(off):
            return struct.unpack_from("<i", sb, off)[0]

        self.bsize = i32(0x030)
        self.fsize = i32(0x034)
        self.frag = i32(0x038)
        self.fsbtodb = i32(0x064)
        self.nindir = i32(0x070)
        self.inopb = i32(0x074)
        self.ipg = i32(0x0B4)
        self.fpg = i32(0x0B8)
        self.ncg = i32(0x02C)
        self.iblkno = i32(0x010)

        if self.bsize <= 0 or self.bsize & (self.bsize - 1):
            die("fs_bsize unplausibel: %d" % self.bsize)
        if self.fsize <= 0 or self.fsize & (self.fsize - 1):
            die("fs_fsize unplausibel: %d" % self.fsize)
        if self.frag <= 0 or self.bsize != self.fsize * self.frag:
            die("fs_frag passt nicht zu bsize/fsize")
        if self.ipg <= 0 or self.fpg <= 0 or self.ncg <= 0:
            die("Cylinder-Group-Werte unplausibel")
        self.inopb = self.bsize // DINODE_SIZE
        self.nindir = self.bsize // 8
        if self.iblkno >= self.fpg:
            die("fs_iblkno ausserhalb der Group")

    def info(self):
        print("Datei        : %s (%s)" % (self.path.name, human(self.fsize_img)))
        print("Typ          : UFS2 (Orbis OS)")
        print("Blockgroesse : %s   Fragment: %s   frag=%d"
              % (self.bsize, self.fsize, self.frag))
        print("fsbtodb      : %d   Inodes/Block: %d   nindir: %d"
              % (self.fsbtodb, self.inopb, self.nindir))
        print("Groups       : %d   Inodes/Group: %d   Bloecke/Group: %d"
              % (self.ncg, self.ipg, self.fpg))
        print("-> Mount-Referenz: mount -t ufs -o ro,ufstype=ufs2 <img> /mnt/x")

    def _off_frag(self, frag):
        return (frag << self.fsbtodb) * DEV_BSIZE

    def _read_frag(self, frag, size):
        off = self._off_frag(frag)
        if off < 0 or off >= self.fsize_img:
            return b"\0" * size
        self.f.seek(off)
        return self.f.read(size)

    def inode_off(self, ino):
        cg = ino // self.ipg
        idx = ino % self.ipg
        if cg >= self.ncg:
            return None
        frag = cg * self.fpg + self.iblkno + idx // self.inopb
        return self._off_frag(frag) + (idx % self.inopb) * DINODE_SIZE

    def read_inode(self, ino):
        off = self.inode_off(ino)
        if off is None or off + DINODE_SIZE > self.fsize_img:
            return None
        self.f.seek(off)
        raw = self.f.read(DINODE_SIZE)
        if len(raw) < 0xD0:
            return None
        mode, nlink, uid, gid = struct.unpack_from("<HhII", raw, 0)
        size = struct.unpack_from("<Q", raw, 0x10)[0]
        if mode == 0:
            return None
        db = list(struct.unpack_from("<12Q", raw, 0x70))
        ib = list(struct.unpack_from("<3Q", raw, 0xD0))
        return dict(ino=ino, mode=mode, nlink=nlink, uid=uid, gid=gid,
                    size=size, db=db, ib=ib)

    def _indirect(self, blkno):
        if blkno == 0:
            return [0] * self.nindir
        data = self._read_frag(blkno * self.frag, self.bsize)
        if len(data) < self.bsize:
            data = data.ljust(self.bsize, b"\0")
        return list(struct.unpack("<%dQ" % self.nindir, data))

    def bmap(self, inode, lbn):
        """Logische Blocknummer -> Liste von Fragmenten (oder None bei Loch)."""
        if lbn < 12:
            blk = inode["db"][lbn]
            return None if blk == 0 else [blk * self.frag + i for i in range(self.frag)]
        lbn -= 12
        if lbn < self.nindir:
            blk = self._indirect(inode["ib"][0])[lbn]
            return None if blk == 0 else [blk * self.frag + i for i in range(self.frag)]
        lbn -= self.nindir
        if lbn < self.nindir ** 2:
            first = self._indirect(inode["ib"][1])[lbn // self.nindir]
            if first == 0:
                return None
            blk = self._indirect(first)[lbn % self.nindir]
            return None if blk == 0 else [blk * self.frag + i for i in range(self.frag)]
        lbn -= self.nindir ** 2
        if lbn < self.nindir ** 3:
            first = self._indirect(inode["ib"][2])[lbn // (self.nindir ** 2)]
            if first == 0:
                return None
            second = self._indirect(first)[(lbn // self.nindir) % self.nindir]
            if second == 0:
                return None
            blk = self._indirect(second)[lbn % self.nindir]
            return None if blk == 0 else [blk * self.frag + i for i in range(self.frag)]
        return None

    def read_file(self, inode, limit=None):
        want = inode["size"] if limit is None else min(limit, inode["size"])
        out = bytearray()
        lbn = 0
        while len(out) < want:
            frags = self.bmap(inode, lbn)
            if frags is None:
                out += b"\0" * self.bsize
            else:
                for frag in frags:
                    if len(out) >= want:
                        break
                    out += self._read_frag(frag, self.fsize)
            lbn += 1
        return bytes(out[:want])

    def readdir(self, inode):
        data = self.read_file(inode)
        pos = 0
        while pos + 8 <= len(data):
            ino, reclen, dtype, namlen = struct.unpack_from("<IHBB", data, pos)
            if reclen < 8 or pos + reclen > len(data):
                break
            name = data[pos + 8:pos + 8 + namlen].decode("latin-1", "replace")
            if ino and name not in (".", ".."):
                yield ino, dtype, name
            pos += reclen

    def listdir(self, ino):
        node = self.read_inode(ino)
        if node is None:
            return []
        if not statmod.S_ISDIR(node["mode"]):
            return []
        return list(self.readdir(node))

    def stat(self, ino):
        n = self.read_inode(ino)
        if n is None:
            return "Inode %d: leer/ungueltig" % ino
        kind = ("dir" if statmod.S_ISDIR(n["mode"]) else
                "symlink" if statmod.S_ISLNK(n["mode"]) else
                "file" if statmod.S_ISREG(n["mode"]) else
                "dev" if statmod.S_ISCHR(n["mode"]) or statmod.S_ISBLK(n["mode"]) else "?")
        s = "Inode %-8d %-7s mode=%04o nlink=%d uid=%d gid=%d size=%s" % (
            ino, kind, n["mode"], n["nlink"], n["uid"], n["gid"], human(n["size"]))
        if statmod.S_ISLNK(n["mode"]) and n["size"] < 120:
            s += "\n  -> " + self.read_file(n, 120).split(b"\0")[0].decode("latin-1", "replace")
        return s

    def walk(self, ino=UFS_ROOTINO, prefix="/"):
        for child, dtype, name in self.listdir(ino):
            path = prefix + name
            yield path, child
            n = self.read_inode(child)
            if n and statmod.S_ISDIR(n["mode"]):
                yield from self.walk(child, path + "/")


# ============================================================== FAT / TEXFAT
class FAT:
    def __init__(self, path):
        self.path = Path(path)
        self.f = open(self.path, "rb")
        self.img_size = self.path.stat().st_size
        self._parse_bpb()

    def close(self):
        self.f.close()

    def _parse_bpb(self):
        self.f.seek(0)
        b = self.f.read(512)
        if len(b) < 512:
            die("Bootsektor zu kurz")
        texfat = b"TEXFAT" in b[:0x200]
        bps = struct.unpack_from("<H", b, 0x0B)[0]
        spc = b[0x0D]
        if bps not in (512, 1024, 2048, 4096):
            bps = 512
        if spc == 0 or spc & (spc - 1):
            spc = 128 if texfat else 1
        self.bps = bps
        self.spc = spc
        self.cluster_size = bps * spc
        self.reserved = struct.unpack_from("<H", b, 0x0E)[0] or 32
        self.num_fats = b[0x10] or 2
        self.root_entries = struct.unpack_from("<H", b, 0x11)[0]
        tot16 = struct.unpack_from("<H", b, 0x13)[0]
        fat16 = struct.unpack_from("<H", b, 0x16)[0]
        tot32 = struct.unpack_from("<I", b, 0x20)[0]
        fat32 = struct.unpack_from("<I", b, 0x24)[0]
        self.root_cluster = struct.unpack_from("<I", b, 0x2C)[0]

        self.fat_start = self.reserved * self.bps
        self.fat_size = (fat32 or fat16) * self.bps
        self.total_sectors = tot32 or tot16
        if not self.total_sectors:
            self.total_sectors = self.img_size // self.bps

        self.root_start = self.fat_start + self.num_fats * self.fat_size
        self.data_start = self.root_start + (self.root_entries * 32)
        clusters = (self.img_size - self.data_start) // self.cluster_size
        if clusters < 65525:
            self.bits = 12 if clusters < 4085 else 16
        else:
            self.bits = 32
        if self.bits != 32 and not self.root_entries:
            self.root_entries = 512
            self.data_start = self.root_start + self.root_entries * 32
        self.label = b[0x47:0x52].decode("latin-1", "replace").strip("\0 ")
        self.fat_type = "TEXFAT" if texfat else "FAT%d" % self.bits

    def info(self):
        print("Datei        : %s (%s)" % (self.path.name, human(self.img_size)))
        print("Typ          : %s%s" % (self.fat_type, " (Sony-Variante)" if self.fat_type == "TEXFAT" else ""))
        print("Sektor/Clust : %d / %d  -> Cluster %s" % (self.bps, self.spc, human(self.cluster_size)))
        print("FATs         : %d  (Start 0x%X, Groesse %s)" % (self.num_fats, self.fat_start, human(self.fat_size)))
        print("Daten ab     : 0x%X   Root-Cluster: %d   Label: %r"
              % (self.data_start, self.root_cluster, self.label))

    def _fat_entry(self, cl):
        off = self.fat_start + cl * (self.bits // 8)
        self.f.seek(off)
        raw = self.f.read(4)
        if self.bits == 32:
            return struct.unpack_from("<I", raw, 0)[0] & 0x0FFFFFFF
        if self.bits == 16:
            return struct.unpack_from("<H", raw, 0)[0]
        self.f.seek(off - (cl // 2))
        v = struct.unpack("<H", self.f.read(2))[0]
        return (v >> 4) if cl % 2 else (v & 0x0FFF)

    def chain(self, cl, limit=None):
        seen = set()
        while 2 <= cl < 0x0FFFFFF7:
            if cl in seen:
                return
            seen.add(cl)
            yield cl
            if limit and len(seen) >= limit:
                return
            cl = self._fat_entry(cl)

    def cluster_off(self, cl):
        return self.data_start + (cl - 2) * self.cluster_size

    def read_chain(self, cl, size=None):
        out = bytearray()
        for c in self.chain(cl):
            self.f.seek(self.cluster_off(c))
            out += self.f.read(self.cluster_size)
            if size and len(out) >= size:
                break
        return bytes(out[:size]) if size else bytes(out)

    def _entries(self, raw):
        lfn, lfn_parts = "", []
        for i in range(0, len(raw) - 31, 32):
            e = raw[i:i + 32]
            if e[0] == 0x00:
                break
            if e[0] == 0xE5:
                lfn, lfn_parts = "", []
                continue
            attr = e[0x0B]
            if attr == ATTR_LFN:
                seq = e[0] & 0x1F
                chunk = e[1:11] + e[14:26] + e[28:32]
                lfn_parts.append((seq, chunk.decode("utf-16-le", "replace")))
                continue
            if attr & ATTR_VOLUME:
                lfn, lfn_parts = "", []
                continue
            if lfn_parts:
                lfn = "".join(t for _, t in sorted(lfn_parts))
                lfn = lfn.split("\0")[0]
            base = e[0:8].decode("latin-1", "replace").rstrip()
            ext = e[8:11].decode("latin-1", "replace").rstrip()
            short = base + ("." + ext if ext else "")
            name = lfn or short
            lfn, lfn_parts = "", []
            cl = struct.unpack_from("<H", e, 0x1A)[0]
            if self.bits == 32:
                cl |= struct.unpack_from("<H", e, 0x14)[0] << 16
            size = struct.unpack_from("<I", e, 0x1C)[0]
            yield dict(name=name, attr=attr, cluster=cl, size=size,
                       is_dir=bool(attr & ATTR_DIR))

    def listdir(self, cluster):
        if cluster == 0:
            self.f.seek(self.root_start)
            raw = self.f.read(self.root_entries * 32)
        else:
            raw = self.read_chain(cluster)
        return list(self._entries(raw))

    def walk(self, cluster=None, prefix="/"):
        if cluster is None:
            cluster = self.root_cluster if self.bits == 32 else 0
        for e in self.listdir(cluster):
            path = prefix + e["name"]
            yield path, e
            if e["is_dir"] and e["cluster"] >= 2:
                yield from self.walk(e["cluster"], path + "/")

    def read_file(self, e):
        if e["cluster"] < 2:
            return b""
        return self.read_chain(e["cluster"], e["size"])


# ============================================================== Kommandos
def open_fs(path):
    with open(path, "rb") as f:
        head = f.read(0x8000)
    if len(head) > SBLOCK_UFS2 + FS_MAGIC_OFF + 4:
        if struct.unpack_from("<I", head, SBLOCK_UFS2 + FS_MAGIC_OFF)[0] == UFS2_MAGIC:
            return UFS2(path)
    return FAT(path)


def cmd_info(a):
    fs = open_fs(a.image)
    fs.info()
    fs.close()


def cmd_list(a):
    fs = open_fs(a.image)
    if isinstance(fs, UFS2):
        ino = UFS_ROOTINO
        if a.path not in ("/", ""):
            for p, i in fs.walk():
                if p == "/" + a.path.strip("/"):
                    ino = i
                    break
            else:
                die("Pfad nicht gefunden: %s" % a.path)
        for child, dtype, name in fs.listdir(ino):
            n = fs.read_inode(child)
            if n is None:
                continue
            kind = "d" if statmod.S_ISDIR(n["mode"]) else \
                   "l" if statmod.S_ISLNK(n["mode"]) else "-"
            print("%s %10d  %s" % (kind, n["size"], name))
    else:
        cluster = fs.root_cluster if fs.bits == 32 else 0
        if a.path not in ("/", ""):
            for p, e in fs.walk():
                if p == "/" + a.path.strip("/"):
                    cluster = e["cluster"]
                    break
            else:
                die("Pfad nicht gefunden: %s" % a.path)
        for e in fs.listdir(cluster):
            print("%s %10d  %s" % ("d" if e["is_dir"] else "-", e["size"], e["name"]))
    fs.close()


def cmd_tree(a):
    fs = open_fs(a.image)
    if isinstance(fs, UFS2):
        for p, i in fs.walk():
            n = fs.read_inode(i)
            if n:
                print("%10d  %s" % (n["size"], p))
    else:
        for p, e in fs.walk():
            print("%10d  %s" % (e["size"], p))
    fs.close()


def cmd_cat(a):
    fs = open_fs(a.image)
    data = None
    if isinstance(fs, UFS2):
        for p, i in fs.walk():
            if p == "/" + a.path.strip("/"):
                n = fs.read_inode(i)
                if n:
                    data = fs.read_file(n)
                break
    else:
        for p, e in fs.walk():
            if p == "/" + a.path.strip("/") and not e["is_dir"]:
                data = fs.read_file(e)
                break
    fs.close()
    if data is None:
        die("nicht gefunden")
    if a.out:
        Path(a.out).write_bytes(data)
        ok("%s (%s)" % (a.out, human(len(data))))
    else:
        sys.stdout.buffer.write(data[:a.limit])


def cmd_extract(a):
    fs = open_fs(a.image)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    count = 0
    if isinstance(fs, UFS2):
        for p, i in fs.walk():
            n = fs.read_inode(i)
            if n is None or statmod.S_ISDIR(n["mode"]):
                continue
            parts = [safe_name(x, set()) for x in p.strip("/").split("/")]
            dst = out.joinpath(*parts)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if statmod.S_ISLNK(n["mode"]):
                tgt = fs.read_file(n, 120).split(b"\0")[0]
                dst.write_bytes(tgt)
            else:
                dst.write_bytes(fs.read_file(n))
            count += 1
            if count % 200 == 0:
                print("  ... %d" % count)
    else:
        for p, e in fs.walk():
            if e["is_dir"]:
                continue
            parts = [safe_name(x, set()) for x in p.strip("/").split("/")]
            dst = out.joinpath(*parts)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(fs.read_file(e))
            count += 1
            if count % 200 == 0:
                print("  ... %d" % count)
    fs.close()
    ok("%d Dateien -> %s" % (count, out))


def cmd_stat(a):
    fs = open_fs(a.image)
    if isinstance(fs, UFS2):
        for p, i in fs.walk():
            if p == "/" + a.path.strip("/"):
                print(fs.stat(i))
                break
        else:
            die("nicht gefunden")
    else:
        for p, e in fs.walk():
            if p == "/" + a.path.strip("/"):
                print("attr=0x%02X cluster=%d size=%d name=%s"
                      % (e["attr"], e["cluster"], e["size"], e["name"]))
                break
        else:
            die("nicht gefunden")
    fs.close()


def main():
    ap = argparse.ArgumentParser(prog="ps4fwkit_fs",
                                 description="Read-only UFS2/FAT/TEXFAT-Parser fuer PS4-Images")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, needpath in (("info", cmd_info, False), ("list", cmd_list, True),
                               ("tree", cmd_tree, False), ("cat", cmd_cat, True),
                               ("extract", cmd_extract, False), ("stat", cmd_stat, True)):
        p = sub.add_parser(name)
        p.add_argument("image")
        if needpath:
            p.add_argument("path", nargs="?", default="/")
        if name == "cat":
            p.add_argument("-o", "--out")
            p.add_argument("--limit", type=int, default=1 << 20)
        if name == "extract":
            p.add_argument("-o", "--out", default="fs_out")
        p.set_defaults(func=fn)
    a = ap.parse_args()
    try:
        a.func(a)
    except FileNotFoundError as e:
        die("nicht gefunden: %s" % e.filename)


if __name__ == "__main__":
    main()
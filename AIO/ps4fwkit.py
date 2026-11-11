#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ps4fwkit v1.1 - All-in-One PS4 Firmware Toolkit
================================================
Container (SLB2/BLS) zerlegen, PUP-Fragmente parsen, SLB2/SLB bauen,
IMG-Dateien identifizieren/carven, SELF-Header lesen, hexen, patchen,
suchen, diffen, Entropie messen, AES/XOR, HMAC verifizieren.

Neu in 1.1: Verzeichnisse werden erkannt und gescannt, PermissionError
wird abgefangen, fehlende Key-Dateien sind kein Absturzgrund mehr.

Struktur:
  SLB2/BLS-Header   32 Byte : magic "SLB2", version, flags, file_count,
                              block_count, reserved[12]
  SLB2-Entry        48 Byte : block_offset(u32, x512), size(u32),
                              reserved[8], name[32]
  PUP-Fragment-Header 0x20  : magic 4F153D1D, unk04, unk08, flags(u8),
                              unk0B, header_size(u16), metadata_size(u16),
                              [ab 0x10 AES-verschluesselt] file_size(u64),
                              segment_count(u16), meta_entries(u16), unk1C
  PUP-Segment       0x20    : flags(u32), pad(u32), offset(u64),
                              compressed_size(u64), uncompressed_size(u64)
  PUP-Metadata      0x50    : aes128_key[16], aes128_iv[16], digest[32],
                              digest_key[16]

Segment-Flags:
  id = flags >> 20          bit0  info-Segment
  bit1 verschluesselt       bit2  signiert
  bit3 komprimiert (zlib)   bit11 blockbasiert
  bit16 digests             bits12-15 Blockgroessen-Shift
  high nibble 0xE = Zusatzsignatur, 0xF = Wasserzeichen
"""

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

VERSION = "1.1"
PUP_MAGIC = b"\x4F\x15\x3D\x1D"
SLB2_MAGIC = b"SLB2"
SELF_MAGIC = b"\x54\x14\xF5\xEE"
ELF_MAGIC = b"\x7FELF"
UFS2_MAGIC = 0x19540119

SCAN_LIMIT = 5000

# ---------------------------------------------------------------- Komponenten

UNKNOWN = dict(name="unknown", dev="?", desc="unbekannt / reserviert",
               exploit="nicht untersucht", crypto="?", rank="info")

IDS = {
    0: dict(UNKNOWN, name="reserved"),
    1: dict(name="emc_ipl.slb", dev="/dev/sflash0s0x32b",
            desc="EMC IPL (Aeolia Rev1). Initial Program Load des EMC-Coprozessors "
                 "im SPI-Flash. EMC verwaltet Power/Reset/Standby.",
            exploit="Boot-Chain: EMC laeuft vor dem x86. Bugs hier = Code vor der "
                    "Signaturpruefung. Godmode-Patches via cfw-toolkit.",
            crypto="AES, Keys nur aus Konsole; Re-Encrypt moeglich", rank="hoch"),
    2: dict(name="eap_kbl.slb", dev="/dev/sflash0s0x33",
            desc="EAP Key Blob Loader (Aeolia Rev1). Entschluesselt und entpackt "
                 "den EAP-Kernel; haelt Keyblobs im SPI-Flash.",
            exploit="Enthaelt Keyblobs -> Angriffspunkt fuer Key-Extraktion und "
                    "fuer Boot-Chain-Manipulation.",
            crypto="AES, Keys nur aus Konsole", rank="kritisch"),
    3: dict(name="wlan_firmware.bin", dev="/dev/sflash0s0x38",
            desc="WLAN-Firmware (Torus2, Aeolia A2). Marvell-WLAN.",
            exploit="WLAN-Stack, teils ungepackt. Fuer Funk-Exploits.", crypto="klartext/zip", rank="mittel"),
    4: dict(name="secure_loader.slb", dev="/dev/sflash0s1.cryptx2b",
            desc="Secure Loader (SAMU IPL-Kette), per SOCUID. Erste Stufe nach BootROM.",
            exploit="Zentrale Boot-Chain-Stufe. Ohne Bruch hier kein echtes CFW per PUP.",
            crypto="signiert, Private Keys NICHT auf Konsole", rank="kritisch"),
    5: dict(name="coreos.img", dev="/dev/sflash0s1.cryptx3b",
            desc="COREOS = Orbis OS. Enthaelt kernel.elf, libkernel.sprx, "
                 "SceSysCore.elf, SceShellCore.elf, alle Kernel-Module.",
            exploit="DAS Ziel fuer Kernel-LPE (5.05/6.72/7.55/9.00er Ketten). "
                    "Syscall-/Device-Bugs, SceSysCore-Handler, Race Conditions.",
            crypto="AES + HMAC, Keys aus Konsole", rank="kritisch"),
    6: dict(name="system_fs_image.img", dev="/dev/da0x4b.crypt",
            desc="System-Partition (FAT32, spaeter TEXFAT). Usermode-Libs, u.a. "
                 "libSceWebKit2.sprx, libSceNKWebKit, Netzwerk-Stack.",
            exploit="WebKit-RCE wohnt hier (libSceWebKit2). Einstiegspunkt jeder "
                    "Browser-Kette. Auch netcontrol-Surface.",
            crypto="AES, Keys aus Konsole", rank="kritisch"),
    7: dict(name="eap_kernel.img", dev="/dev/da0x2",
            desc="EAP-Kernel (ARM, Southbridge). Laeuft parallel zum x86, "
                 "verwaltet HDD-Key, Auth, Rest-Mode.",
            exploit="Aeolia/Aux-Hax: ARM-Seite, eigener Heap, oft schlampiger Code. "
                    "HDD-Key-Dump, Rest-Mode-Angriffe.",
            crypto="AES, Keys aus Konsole", rank="hoch"),
    8: dict(name="eap_vsh_fs_image.img", dev="/dev/da0x3.crypt",
            desc="EAP-VSH-Dateisystem (FAT16). Usermode-Daemons auf dem EAP.",
            exploit="Angriffsflaeche gegen die EAP-Usermode-Services.", crypto="AES", rank="hoch"),
    9: dict(name="recovery_fs_image.img", dev="/dev/da0x0.crypt",
            desc="Recovery-Partition (Safe Mode).", exploit="Recovery-Flows, PUP-Install-Pfad.",
            crypto="AES", rank="mittel"),
    0x0A: dict(name="sflash_x40.bin", dev="/dev/sflash0s1.cryptx40",
               desc="Unbekannter SPI-Flash-Bereich.", exploit="nicht untersucht", crypto="AES", rank="info"),
    0x0B: dict(name="preinst_fs_image.img", dev="/dev/da0x1.crypt",
               desc="Preinstall-Partition.", exploit="Werks-Preinstall", crypto="AES", rank="niedrig"),
    0x0C: dict(name="system_ex_fs_image.img", dev="/dev/da0x5b.crypt",
               desc="system_ex-Partition: zusaetzliche System-Apps.", exploit="Zusatz-Apps, seltener Ziel",
               crypto="AES", rank="mittel"),
    0x0D: dict(name="emc_ipl_a2.slb", dev="/dev/sflash0s0x32b",
               desc="EMC IPL, Aeolia A2 (CXD90025G).", exploit="wie Index 1", crypto="AES", rank="hoch"),
    0x0E: dict(name="eap_kbl_a2.slb", dev="/dev/sflash0s0x33",
               desc="EAP KBL, Aeolia A2.", exploit="wie Index 2", crypto="AES", rank="kritisch"),
    0x0F: dict(name="test.bin", dev="test", desc="Test-Segment.", exploit="-", crypto="-", rank="info"),
    0x10: dict(name="sbram_10.bin", dev="/dev/sbram0", desc="SBRAM-Bereich.", exploit="-", crypto="-", rank="info"),
    0x11: dict(name="sbram_11.bin", dev="/dev/sbram0", desc="SBRAM-Bereich.", exploit="-", crypto="-", rank="info"),
    0x12: dict(name="sbram_12.bin", dev="/dev/sbram0", desc="SBRAM-Bereich.", exploit="-", crypto="-", rank="info"),
    0x13: dict(name="sbram_13.bin", dev="/dev/sbram0", desc="SBRAM-Bereich.", exploit="-", crypto="-", rank="info"),
    0x14: dict(name="sbram_14.bin", dev="/dev/sbram0", desc="SBRAM-Bereich.", exploit="-", crypto="-", rank="info"),
    0x15: dict(name="sbram_15.bin", dev="/dev/sbram0", desc="SBRAM-Bereich.", exploit="-", crypto="-", rank="info"),
    0x16: dict(name="sbram_16.bin", dev="/dev/sbram0", desc="SBRAM-Bereich.", exploit="-", crypto="-", rank="info"),
    0x20: dict(name="emc_ipl_belize.slb", dev="/dev/sflash0s0x32b",
               desc="EMC IPL, Belize Rev1 (CXD90036G).", exploit="wie Index 1", crypto="AES", rank="hoch"),
    0x21: dict(name="eap_kbl_belize.slb", dev="/dev/sflash0s0x33",
               desc="EAP KBL, Belize Rev1.", exploit="wie Index 2", crypto="AES", rank="kritisch"),
    0x22: dict(name="wlan_firmware_belize.bin", dev="/dev/sflash0s0x38",
               desc="WLAN-FW Torus2 Belize.", exploit="Funk-Stack", crypto="klartext", rank="mittel"),
    0x23: dict(name="secure_loader_2.slb", dev="/dev/sflash0s1.cryptx2b",
               desc="Secure Loader, 2. SOCUID (CXD90026AG).", exploit="Boot-Chain", crypto="signiert", rank="kritisch"),
    0x24: dict(name="emc_ipl_baikal.slb", dev="/dev/sflash0s0x32b",
               desc="EMC IPL, Baikal B1 (CXD90046GG).", exploit="wie Index 1", crypto="AES", rank="hoch"),
    0x25: dict(name="eap_kbl_baikal.slb", dev="/dev/sflash0s0x33",
               desc="EAP KBL, Baikal B1.", exploit="wie Index 2", crypto="AES", rank="kritisch"),
    0x26: dict(name="secure_loader_3.slb", dev="/dev/sflash0s1.cryptx2b",
               desc="Secure Loader, 3. SOCUID (CXD90037G).", exploit="Boot-Chain", crypto="signiert", rank="kritisch"),
    0x27: dict(name="secure_loader_4.slb", dev="/dev/sflash0s1.cryptx2b",
               desc="Secure Loader, 4. SOCUID (CXD90043GB).", exploit="Boot-Chain", crypto="signiert", rank="kritisch"),
    0x28: dict(name="emc_ipl_baikal_b.slb", dev="/dev/sflash0s0x32b",
               desc="EMC IPL, Baikal Rev1.", exploit="wie Index 1", crypto="AES", rank="hoch"),
    0x2A: dict(name="emc_ipl_belize2.slb", dev="/dev/sflash0s0x32b",
               desc="EMC IPL, Belize2 A0.", exploit="wie Index 1", crypto="AES", rank="hoch"),
    0x2B: dict(name="eap_kbl_belize2.slb", dev="/dev/sflash0s0x33",
               desc="EAP KBL, Belize2 A0.", exploit="wie Index 2", crypto="AES", rank="kritisch"),
    0x2C: dict(name="emc_ipl_baikal2.slb", dev="/dev/sflash0s0x32b",
               desc="EMC IPL, Baikal2.", exploit="wie Index 1", crypto="AES", rank="hoch"),
    0x2D: dict(name="secure_loader_5.slb", dev="/dev/sflash0s1.cryptx2b",
               desc="Secure Loader, 5. SOCUID (CXD90044GB).", exploit="Boot-Chain", crypto="signiert", rank="kritisch"),
    0x2E: dict(name="emc_ipl_belize2_c.slb", dev="/dev/sflash0s0x32b",
               desc="EMC IPL, Belize2 3rd Rev.", exploit="wie Index 1", crypto="AES", rank="hoch"),
    0x30: dict(name="wlan_firmware_trooper.bin", dev="/dev/sflash0s0x38",
               desc="WLAN-FW Trooper/Belize2.", exploit="Funk-Stack", crypto="klartext", rank="mittel"),
    0x31: dict(name="secure_loader_6.slb", dev="/dev/sflash0s1.cryptx2b",
               desc="Secure Loader, 6. SOCUID (CXD90051GB).", exploit="Boot-Chain", crypto="signiert", rank="kritisch"),
    0x32: dict(name="secure_loader_7.slb", dev="/dev/sflash0s1.cryptx2b",
               desc="Secure Loader, 7. SOCUID (CXD90055GB).", exploit="Boot-Chain", crypto="signiert", rank="kritisch"),
    0x101: dict(name="eula.xml", dev="-", desc="Lizenzvereinbarung.", exploit="keine", crypto="klartext", rank="info"),
    0x200: dict(name="orbis_swu.self", dev="-", desc="Orbis Software Updater (ELF). Liest und "
                "validiert das PUP auf der Konsole.", exploit="Parsing-Oberflaeche des Updaters",
                crypto="SELF signiert", rank="hoch"),
    0x202: dict(name="orbis_swu_enc.self", dev="-", desc="Orbis SWU, verschluesselte SELF-Variante.",
                exploit="wie 0x200", crypto="SELF signiert", rank="hoch"),
    0x301: dict(name="update_301.bin", dev="/update", desc="/update-bezogen.", exploit="-", crypto="-", rank="info"),
    0x302: dict(name="update_302.bin", dev="/update", desc="/update-bezogen.", exploit="-", crypto="-", rank="info"),
    0xD00: dict(name="syscon_firmware.bin", dev="/dev/sc_fw_update0",
                desc="Syscon-Firmware (4000xxxx). Eigener MCU, ueberwacht Power/Reset/Temps.",
                exploit="Syscon-Glitching fuer Downgrade; Puffer-/Protokoll-Bugs.",
                crypto="AES, Keys aus Konsole", rank="kritisch"),
    0xD01: dict(name="bluray_drive_firmware.bin", dev="/dev/cd0",
                desc="Bluray-Laufwerks-Firmware, alle Revisionen (4XXR).", exploit="BD-J / Laufwerks-Protokoll",
                crypto="AES", rank="mittel"),
    0xD02: dict(name="usb_sata_bridge_firmware.bin", dev="/dev/da0",
                desc="USB-SATA-Bridge-FW (MB86C311B).", exploit="Bridge-Protokoll", crypto="AES", rank="niedrig"),
    0xD07: dict(name="syscon_patch.bin", dev="/dev/sc_fw_update0",
                desc="Syscon-Patch (4001xxxx).", exploit="Syscon-Verhalten, Downgrade-relevant", crypto="AES", rank="hoch"),
    0xD08: dict(name="syscon_firmware_devkit.bin", dev="/dev/sc_fw_update0",
                desc="Syscon-FW, DevKit-Variante.", exploit="wie 0xD00", crypto="AES", rank="mittel"),
    0xD09: dict(name="cp_firmware.bin", dev="cpfirm",
                desc="Communication-Processor-FW (nur DevKit).", exploit="nicht untersucht", crypto="-", rank="info"),
}

RANK_ORDER = {"kritisch": 0, "hoch": 1, "mittel": 2, "niedrig": 3, "info": 4}


def ident(idx):
    d = IDS.get(idx)
    if d is None:
        return dict(UNKNOWN, name="unknown_%03X" % idx)
    return d


# ------------------------------------------------------------------- Utilities

def align_up(v, a):
    return (v + a - 1) // a * a


def human(n):
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or u == "TiB":
            return ("%d %s" % (n, u)) if u == "B" else ("%.2f %s" % (n, u))
        n /= 1024.0


def entropy(buf):
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = float(len(buf))
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def hexdump(data, base=0, width=16):
    out = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hx = " ".join("%02X" % b for b in chunk).ljust(width * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%08X  %s  |%s|" % (base + off, hx, asc))
    return "\n".join(out)


def read_at(fp, off, size):
    fp.seek(off)
    return fp.read(size)


def die(msg, code=1):
    print("[!] " + msg, file=sys.stderr)
    sys.exit(code)


def ok(msg):
    print("[+] " + msg)


def warn(msg):
    print("[~] " + msg)


# ------------------------------------------------------------------------ AES

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
INV_SBOX = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d")
RCON = bytes.fromhex("01020408102040801b36")


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


class AES:
    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES-Key muss 16/24/32 Byte sein")
        self.nk = len(key) // 4
        self.nr = self.nk + 6
        self.rk = self._expand(key)

    def _expand(self, key):
        w = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
        for i in range(self.nk, 4 * (self.nr + 1)):
            t = list(w[i - 1])
            if i % self.nk == 0:
                t = t[1:] + t[:1]
                t = [SBOX[b] for b in t]
                t[0] ^= RCON[i // self.nk - 1]
            elif self.nk > 6 and i % self.nk == 4:
                t = [SBOX[b] for b in t]
            w.append([w[i - self.nk][j] ^ t[j] for j in range(4)])
        return [sum(w[4 * r:4 * r + 4], []) for r in range(self.nr + 1)]

    def _ark(self, s, r):
        for i in range(16):
            s[i] ^= self.rk[r][i]

    def encrypt_block(self, blk):
        s = list(blk)
        self._ark(s, 0)
        for r in range(1, self.nr + 1):
            s = [SBOX[b] for b in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
            if r != self.nr:
                t = []
                for c in range(4):
                    a = s[4 * c:4 * c + 4]
                    t += [_gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3],
                          a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3],
                          a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3),
                          _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)]
                s = t
            self._ark(s, r)
        return bytes(s)

    def decrypt_block(self, blk):
        s = list(blk)
        self._ark(s, self.nr)
        for r in range(self.nr - 1, -1, -1):
            s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]
            s = [INV_SBOX[b] for b in s]
            self._ark(s, r)
            if r != 0:
                t = []
                for c in range(4):
                    a = s[4 * c:4 * c + 4]
                    t += [_gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9),
                          _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13),
                          _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11),
                          _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)]
                s = t
        return bytes(s)

    def cbc_encrypt(self, data, iv, pad=True):
        if pad:
            p = 16 - (len(data) % 16)
            data = data + bytes([p]) * p
        out, prev = bytearray(), iv
        for i in range(0, len(data), 16):
            blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
            prev = self.encrypt_block(blk)
            out += prev
        return bytes(out)

    def cbc_decrypt(self, data, iv, unpad=False):
        out, prev = bytearray(), iv
        for i in range(0, len(data) - len(data) % 16, 16):
            blk = data[i:i + 16]
            out += bytes(a ^ b for a, b in zip(self.decrypt_block(blk), prev))
            prev = blk
        if unpad and out:
            p = out[-1]
            if 1 <= p <= 16 and out.endswith(bytes([p]) * p):
                out = out[:-p]
        return bytes(out)

    def ecb_decrypt(self, data):
        return b"".join(self.decrypt_block(data[i:i + 16])
                        for i in range(0, len(data) - len(data) % 16, 16))

    def ecb_encrypt(self, data, pad=True):
        if pad:
            p = 16 - (len(data) % 16)
            data = data + bytes([p]) * p
        return b"".join(self.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))


def parse_key(text):
    text = text.strip()
    if text.startswith("0x"):
        text = text[2:]
    text = text.replace(" ", "").replace(":", "")
    if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) % 2 == 0:
        return bytes.fromhex(text)
    p = Path(text)
    if p.exists():
        return p.read_bytes()
    die("Key/IV nicht lesbar: %r (Hex oder Dateipfad erwartet)" % text)


# ----------------------------------------------------------------------- SLB2

class SLB2:
    """SLB2 / BLS-Container. Wird fuer PS4UPDATE.PUP und fuer .slb benutzt."""

    def __init__(self, path):
        self.path = Path(path)
        self.entries = []
        self.data_start = 0
        self.file_count = 0
        self.block_count = 0
        self.flags = 0
        self.version = 0
        self.prefix = b""

    def parse(self):
        with open(self.path, "rb") as f:
            hdr = f.read(32)
            if len(hdr) < 32 or hdr[:4] != SLB2_MAGIC:
                die("%s ist kein SLB2/BLS-Container (Magic %r)"
                    % (self.path.name, hdr[:4]))
            self.version, self.flags, self.file_count, self.block_count = \
                struct.unpack_from("<IIII", hdr, 4)
            if self.file_count > 4096:
                die("unplausible Entry-Zahl: %d" % self.file_count)
            raw = f.read(48 * self.file_count)
            if len(raw) < 48 * self.file_count:
                die("Entry-Tabelle abgeschnitten")
            for i in range(self.file_count):
                off, size = struct.unpack_from("<II", raw, 48 * i)
                name = raw[48 * i + 16:48 * i + 48].split(b"\0")[0]
                self.entries.append(dict(index=i, sector=off, size=size,
                                         name=name.decode("latin-1")))
            hdr_end = 32 + 48 * self.file_count
            if self.entries:
                self.data_start = min(e["sector"] * 512 for e in self.entries)
            else:
                self.data_start = align_up(hdr_end, 512)
            self.data_start = max(self.data_start, hdr_end)
            self.prefix = read_at(f, hdr_end, self.data_start - hdr_end)
        return self

    def print_table(self):
        print("%-4s %-12s %-10s %-9s %s" % ("#", "Sektor", "Groesse", "Typ", "Name"))
        with open(self.path, "rb") as f:
            for e in self.entries:
                head = read_at(f, e["sector"] * 512, 8)
                if head[:4] == SLB2_MAGIC:
                    t = "SLB2"
                elif head[:4] == PUP_MAGIC:
                    t = "PUP"
                elif head[:4] == ELF_MAGIC:
                    t = "ELF"
                elif head[:2] == b"PK":
                    t = "ZIP"
                elif head[:2] == b"\x1F\x8B":
                    t = "GZIP"
                elif head[:4] == b"<?xm":
                    t = "XML"
                else:
                    t = "-"
                print("%-4d %-12d %-10s %-9s %s"
                      % (e["index"], e["sector"], human(e["size"]), t, e["name"]))

    def extract(self, outdir):
        outdir = Path(outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        with open(self.path, "rb") as f:
            for e in self.entries:
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", e["name"]) or ("entry_%d" % e["index"])
                dst = outdir / ("%02d_%s" % (e["index"], safe))
                dst.write_bytes(read_at(f, e["sector"] * 512, e["size"]))
                ok("%s  (%s)" % (dst.name, human(e["size"])))
        ok("%d Eintraege -> %s" % (len(self.entries), outdir))

    @staticmethod
    def build(srcdir, outfile, version=1, flags=0, keep_prefix=None):
        srcdir = Path(srcdir)
        files = sorted(p for p in srcdir.iterdir() if p.is_file())
        if not files:
            die("Quellverzeichnis leer: %s" % srcdir)
        prefix = keep_prefix or b""
        hdr_end = 32 + 48 * len(files)
        data_start = align_up(hdr_end + len(prefix), 512)
        blobs, entries, cur = [], [], data_start
        for p in files:
            data = p.read_bytes()
            name = p.name.encode("latin-1")[:31]
            entries.append((cur // 512, len(data), name))
            blobs.append((cur, data))
            cur = align_up(cur + len(data), 512)
        out = bytearray()
        out += SLB2_MAGIC
        out += struct.pack("<IIII", version, flags, len(files), cur // 512)
        out += b"\0" * 12
        for sec, size, name in entries:
            out += struct.pack("<II", sec, size) + b"\0" * 8
            out += name.ljust(32, b"\0")
        out += prefix
        out += b"\0" * (data_start - len(out))
        for off, data in blobs:
            out += b"\0" * (off - len(out))
            out += data
            out += b"\0" * (align_up(len(out), 512) - len(out))
        Path(outfile).write_bytes(bytes(out))
        ok("%s geschrieben (%s, %d Eintraege)"
           % (outfile, human(len(out)), len(files)))


# ------------------------------------------------------------------------ PUP

class NeedHeaderKey(Exception):
    pass


class PUP:
    def __init__(self, path, keys=None):
        self.path = Path(path)
        self.keys = keys or {}
        self.header = None
        self.segments = []
        self.metadata = []
        self.info = None
        self.header_len = 0
        self.header_plain = False

    def parse(self):
        with open(self.path, "rb") as f:
            raw = f.read(0x20)
            if len(raw) < 0x20 or raw[:4] != PUP_MAGIC:
                die("%s ist kein PS4-PUP-Fragment (Magic %r)" % (self.path.name, raw[:4]))
            flags = raw[0x0A]
            header_size, meta_size = struct.unpack_from("<HH", raw, 0x0C)
            self.header_plain = bool(flags & 1)
            if header_size != 0x20:
                warn("header_size ungewoehnlich: 0x%X" % header_size)
            self.header_len = header_size + meta_size

            if not self.header_plain:
                key = self.keys.get("pup_header_key")
                iv = self.keys.get("pup_header_iv")
                if not key:
                    raise NeedHeaderKey(
                        "Header ist AES-verschluesselt und kein pup_header_key gesetzt.")
                body = f.read(max(0, self.header_len - 0x20))
                body = AES(parse_key(key)).cbc_decrypt(body, parse_key(iv or "00" * 16))
                plain = raw + body
            else:
                f.seek(0)
                plain = f.read(self.header_len)

        magic, unk04, unk08 = struct.unpack_from("<4sIH", plain, 0)
        flags_b, unk0B = plain[0x0A], plain[0x0B]
        file_size = struct.unpack_from("<Q", plain, 0x10)[0]
        seg_count, meta_entries = struct.unpack_from("<HH", plain, 0x18)
        self.header = dict(magic=magic, unk04=unk04, unk08=unk08, flags=flags_b,
                           unk0B=unk0B, header_size=header_size,
                           metadata_size=meta_size, file_size=file_size,
                           segment_count=seg_count, meta_entries=meta_entries)

        if seg_count > 512:
            die("unplausible Segment-Zahl: %d" % seg_count)
        need = 0x20 + 0x20 * seg_count + 0x30 + 0x50 * seg_count
        if self.header_len < need:
            warn("Header-Laenge %d < erwartet %d - Segment-Tabelle evtl. unvollstaendig"
                 % (self.header_len, need))

        for i in range(seg_count):
            flags_s, _pad, off, csize, usize = struct.unpack_from("<IIQQQ", plain, 0x20 + 0x20 * i)
            self.segments.append(dict(
                index=i, flags=flags_s, id=flags_s >> 20, offset=off,
                csize=csize, usize=usize,
                is_info=bool(flags_s & 1), encrypted=bool(flags_s & 2),
                signed=bool(flags_s & 4), compressed=bool(flags_s & 8),
                has_blocks=bool(flags_s & 0x800), has_digests=bool(flags_s & 0x10000),
                block_shift=((flags_s >> 12) & 0xF) + 12,
                special=flags_s & 0xF0000000))

        info_off = 0x20 + 0x20 * seg_count
        if len(plain) >= info_off + 0x30:
            fw = struct.unpack_from("<I", plain, info_off)[0]
            plat = struct.unpack_from("<I", plain, info_off + 0x18)[0]
            rq = struct.unpack_from("<I", plain, info_off + 0x24)[0]
            self.info = dict(fw_ver=fw, platform=plat, req_fw_ver=rq)

        meta_off = info_off + 0x30
        for i in range(min(seg_count, max(0, (len(plain) - meta_off) // 0x50))):
            blk = plain[meta_off + 0x50 * i: meta_off + 0x50 * (i + 1)]
            self.metadata.append(dict(key=blk[0:16], iv=blk[16:32],
                                      digest=blk[32:64], digest_key=blk[64:80]))
        return self

    @staticmethod
    def version_str(v):
        return "%d.%02X-%04X" % ((v >> 24) & 0xFF, (v >> 16) & 0xFF, v & 0xFFFF)

    def print_info(self):
        h = self.header
        print("Datei            : %s (%s)" % (self.path.name, human(self.path.stat().st_size)))
        print("Header           : %s" % ("KLARTEXT" if self.header_plain else "AES-verschluesselt"))
        print("unk04 / unk08    : 0x%08X / 0x%04X" % (h["unk04"], h["unk08"]))
        print("flags            : 0x%02X   header_size=0x%X  metadata_size=0x%X"
              % (h["flags"], h["header_size"], h["metadata_size"]))
        print("file_size        : %s" % human(h["file_size"]))
        print("Segmente         : %d   Metadata-Entries: %d"
              % (h["segment_count"], h["meta_entries"]))
        if self.info:
            print("FW-Version       : %s" % self.version_str(self.info["fw_ver"]))
            print("Platform-Type    : 0x%X" % self.info["platform"])
            print("Req. FW-Version  : %s" % self.version_str(self.info["req_fw_ver"]))
        print()
        print("%-3s %-6s %-4s %-9s %-10s %-10s %s"
              % ("#", "ID", "Info", "Flags", "Comp", "Uncomp", "Komponente"))
        for s in sorted(self.segments, key=lambda x: RANK_ORDER.get(ident(x["id"])["rank"], 9)):
            d = ident(s["id"])
            fl = ("E" if s["encrypted"] else "-") + ("S" if s["signed"] else "-") + \
                 ("C" if s["compressed"] else "-") + ("B" if s["has_blocks"] else "-")
            tag = "SPEC" if s["special"] in (0xE0000000, 0xF0000000) else ""
            print("%-3d 0x%03X  %-4s %-9s %-10s %-10s %s %s"
                  % (s["index"], s["id"], "ja" if s["is_info"] else "-", fl,
                     human(s["csize"]), human(s["usize"]), d["name"], tag))

    def _inflate(self, data, want):
        o = zlib.decompressobj()
        out = o.decompress(data)
        try:
            out += o.flush()
        except zlib.error:
            pass
        return out[:want] if want else out

    def _decrypt(self, seg, data):
        if not seg["encrypted"]:
            return data
        if seg["index"] >= len(self.metadata):
            warn("Segment %d: keine Metadata - bleibt verschluesselt" % seg["index"])
            return data
        m = self.metadata[seg["index"]]
        return AES(m["key"]).cbc_decrypt(data, m["iv"])

    def extract(self, outdir, only=None, decrypt=True):
        outdir = Path(outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        manifest = []
        with open(self.path, "rb") as f:
            for seg in self.segments:
                if seg["special"] in (0xE0000000, 0xF0000000):
                    continue
                if seg["is_info"]:
                    continue
                if only is not None and seg["id"] not in only:
                    continue
                d = ident(seg["id"])
                name = "%02d_%s" % (seg["id"], d["name"]) if seg["id"] < 100 else \
                       "0x%03X_%s" % (seg["id"], d["name"])
                dst = outdir / name
                if seg["has_blocks"]:
                    data = self._extract_blocked(f, seg, decrypt)
                else:
                    raw = read_at(f, seg["offset"], seg["csize"])
                    if decrypt:
                        raw = self._decrypt(seg, raw)
                    data = self._inflate(raw, seg["usize"]) if seg["compressed"] else raw
                dst.write_bytes(data)
                manifest.append(dict(index=seg["index"], id=seg["id"], name=name,
                                     size=len(data), rank=d["rank"], desc=d["desc"]))
                ok("%s  (%s, Rang: %s)" % (name, human(len(data)), d["rank"]))
        (outdir / "_manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        ok("Manifest -> %s/_manifest.json" % outdir)

    def _find_table(self, idx):
        for s in self.segments:
            if s["is_info"] and s["id"] == idx:
                return s
        return None

    def _extract_blocked(self, f, seg, decrypt):
        tbl = self._find_table(seg["index"])
        if tbl is None:
            die("Segment %d ist blockbasiert, aber Info-Segment fehlt" % seg["index"])
        tdata = read_at(f, tbl["offset"], tbl["csize"])
        if decrypt:
            tdata = self._decrypt(tbl, tdata)
        if tbl["compressed"]:
            tdata = self._inflate(tdata, tbl["usize"])
        bsize = 1 << seg["block_shift"]
        bcount = (bsize + seg["usize"] - 1) // bsize
        tail = seg["usize"] % bsize or bsize
        infos = []
        for j in range(bcount):
            base = 32 * bcount + 8 * j
            if base + 8 > len(tdata):
                break
            infos.append(struct.unpack_from("<II", tdata, base))
        out = bytearray()
        pos = seg["offset"]
        remaining = seg["csize"]
        for i, (boff, bsz) in enumerate(infos):
            rsize = bsize
            is_comp = False
            if seg["compressed"]:
                unpadded = (bsz & ~0xF) - (bsz & 0xF)
                if unpadded != bsize:
                    rsize = bsz
                    if i != bcount - 1 or tail != bsz:
                        rsize &= ~0xF
                        is_comp = True
                if boff:
                    pos = seg["offset"] + boff
            else:
                rsize = min(bsize, remaining)
            chunk = read_at(f, pos, rsize)
            pos += rsize
            remaining -= rsize
            if decrypt:
                chunk = self._decrypt(seg, chunk)
            out += self._inflate(chunk, 0) if is_comp else chunk
        return bytes(out[:seg["usize"]])

    def verify(self):
        bad = 0
        with open(self.path, "rb") as f:
            for seg in self.segments:
                if not seg["has_digests"] or seg["index"] >= len(self.metadata):
                    continue
                m = self.metadata[seg["index"]]
                raw = read_at(f, seg["offset"], seg["csize"])
                mac = hmac.new(m["digest_key"], raw, hashlib.sha256).digest()
                if mac == m["digest"]:
                    print("  [ok]   Segment %-3d HMAC-SHA256 passt" % seg["index"])
                else:
                    print("  [BAD]  Segment %-3d HMAC-SHA256 weicht ab" % seg["index"])
                    bad += 1
        return bad


# ----------------------------------------------------------------------- SELF

def self_info(path):
    data = Path(path).read_bytes()[:0x100]
    if data[:4] not in (SELF_MAGIC, b"\x00SCE"):
        warn("Kein bekanntes SELF-Magic (%r) - zeige trotzdem Header" % data[:4])
    if len(data) >= 0x30:
        ver, = struct.unpack_from("<I", data, 0x04)
        fl, ty = struct.unpack_from("<HH", data, 0x08)
        meta_off, = struct.unpack_from("<I", data, 0x0C)
        hlen, = struct.unpack_from("<Q", data, 0x10)
        elfsz, = struct.unpack_from("<Q", data, 0x18)
        selfsz, = struct.unpack_from("<Q", data, 0x20)
        print("Magic            : %s" % data[:4].hex(" "))
        print("Version          : 0x%X" % ver)
        print("Flags / Type     : 0x%04X / 0x%04X" % (fl, ty))
        print("Metadata-Offset  : 0x%X" % meta_off)
        print("Header-Laenge    : %d" % hlen)
        print("ELF-Groesse      : %s" % human(elfsz))
        print("SELF-Groesse     : %s" % human(selfsz))
        if elfsz and selfsz > elfsz:
            print("-> Nutzlast beginnt bei 0x%X" % (selfsz - elfsz))
    print()
    print(hexdump(Path(path).read_bytes()[:0x80]))


# ------------------------------------------------------------------------ IMG

def img_info(path):
    p = Path(path)
    size = p.stat().st_size
    print("Datei  : %s (%s)" % (p.name, human(size)))
    with open(p, "rb") as f:
        head = f.read(0x10000)
        print("Anfang : %s" % head[:16].hex(" "))
        fs = "unbekannt"
        if len(head) > 0x52 and head[0x52:0x57] == b"FAT32":
            fs = "FAT32"
        elif len(head) > 0x36 and head[0x36:0x3B] in (b"FAT12", b"FAT16"):
            fs = head[0x36:0x3B].decode()
        if len(head) >= 0x8001 and head[0x8001:0x8006] == b"CD001":
            fs = "ISO9660"
        if head[:2] == b"\x1F\x8B":
            fs = "GZIP"
        f.seek(0x10000)
        sb = f.read(0x800)
        if len(sb) > 0x560 and struct.unpack_from("<I", sb, 0x55C)[0] == UFS2_MAGIC:
            fs = "UFS2 (Orbis OS)"
        if b"TEXFAT" in head[:0x400]:
            fs = "TEXFAT (Sony-Variante)"
        print("Dateisystem: %s" % fs)
        if fs == "UFS2 (Orbis OS)":
            print("-> Linux: mount -t ufs -o ro,ufstype=ufs2 <img> /mnt/x")
            print("-> oder: python ps4fwkit_ext.py fs extract <img> -o out")
        elif fs.startswith("FAT") or fs == "TEXFAT":
            print("-> 7z x <img> oder python ps4fwkit_ext.py fs extract <img> -o out")
    with open(p, "rb") as f:
        ents = entropy(f.read(1 << 20))
    print("Entropie   : %.3f bit/Byte %s"
          % (ents, "(komprimiert/verschluesselt)" if ents > 7.4 else ""))


MAGICS = [
    (SLB2_MAGIC, "SLB2-Container"), (PUP_MAGIC, "PUP-Fragment"),
    (ELF_MAGIC, "ELF"), (b"\x1F\x8B\x08", "GZIP"), (b"PK\x03\x04", "ZIP"),
    (b"\x89PNG", "PNG"), (b"<?xml", "XML"), (b"SCEUF", "SCEUF (PSP/PS3/Vita)"),
]


def carve(path, min_size=64):
    data = Path(path).read_bytes()
    hits = 0
    for magic, label in MAGICS:
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            print("0x%08X  %-22s %s" % (i, label, data[i:i + 16].hex(" ")))
            hits += 1
            start = i + 1
    ok("%d Treffer" % hits)


# ------------------------------------------------------------ Identifikation

def describe(p):
    """Typ einer Datei anhand der Magic bestimmen, ohne gross zu lesen."""
    try:
        with open(p, "rb") as f:
            head = f.read(0x40)
    except PermissionError:
        return "gesperrt", "in Benutzung"
    except OSError as e:
        return "Fehler", str(e)
    if head[:4] == SLB2_MAGIC:
        n = int.from_bytes(head[0x0C:0x10], "little")
        return "SLB2-Container", "%d Eintraege" % n
    if head[:4] == PUP_MAGIC:
        return "PUP-Fragment", "Header %s" % ("klartext" if head[0x0A] & 1 else "AES")
    if head[:4] in (SELF_MAGIC, b"\x00SCE"):
        return "SELF", ""
    if head[:4] == ELF_MAGIC:
        return "ELF", ""
    if head[:2] == b"PK":
        return "ZIP", ""
    if head[:2] == b"\x1F\x8B":
        return "GZIP", ""
    if head[:4] == b"SCEUF":
        return "SCEUF (PSP/PS3/Vita)", ""
    if head[:4] == b"<?xm":
        return "XML", ""
    if not head:
        return "leer", ""
    return "unbekannt", ""


def scan_dir(d):
    d = Path(d)
    rows, hashes, crit, seen = [], {}, [], 0
    for p in sorted(d.rglob("*")):
        if not p.is_file():
            continue
        seen += 1
        if seen > SCAN_LIMIT:
            warn("Scan bei %d Dateien abgebrochen (SCAN_LIMIT)" % SCAN_LIMIT)
            break
        typ, extra = describe(p)
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        rows.append((typ, size, p, extra))
        try:
            with open(p, "rb") as f:
                h = hashlib.sha256(f.read(1 << 20)).hexdigest()
            hashes.setdefault(h, []).append(p.name)
        except OSError:
            pass
        low = p.name.lower()
        for meta in IDS.values():
            if meta["name"].split(".")[0] in low and meta["rank"] in ("kritisch", "hoch"):
                crit.append((meta["rank"], p.name, meta["desc"]))
                break

    print("Verzeichnis : %s" % d)
    print("Dateien     : %d, Gesamt %s\n" % (len(rows), human(sum(r[1] for r in rows))))
    print("%-26s %-10s %s" % ("Typ", "Groesse", "Name"))
    for typ, size, p, extra in rows:
        mark = " *" if typ in ("PUP-Fragment", "SLB2-Container") else ""
        try:
            rel = p.relative_to(d)
        except ValueError:
            rel = p.name
        print("%-26s %-10s %s%s%s"
              % (typ, human(size), rel, mark, ("  [" + extra + "]") if extra else ""))

    dups = {h: n for h, n in hashes.items() if len(n) > 1}
    if dups:
        print("\nDoppelte Inhalte:")
        for names in dups.values():
            print("  " + " == ".join(names))

    if crit:
        print("\nFirmware-relevante Funde (nach Rang):")
        for rank, name, desc in sorted(crit, key=lambda x: RANK_ORDER[x[0]]):
            print("  [%s] %-30s %s" % (rank, name, desc[:70]))

    pups = [p for typ, _, p, _ in rows if typ == "PUP-Fragment"]
    if pups:
        print("\nWeiter mit:")
        for p in pups:
            print('  python ps4fwkit.py pup info "%s"' % p)
    slbs = [p for typ, _, p, _ in rows if typ == "SLB2-Container"]
    if slbs:
        print("\nSLB2-Container entpacken mit 'slb extract' (Menuepunkt 3).")
    if any(typ == "gesperrt" for typ, _, _, _ in rows):
        print("\nHinweis: gesperrte Dateien laufen gerade in einem anderen Prozess.")


# ------------------------------------------------------------------- Kommandos

def cmd_info(a):
    p = Path(a.file)
    if p.is_dir():
        scan_dir(p)
        return
    with open(p, "rb") as f:
        magic = f.read(4)
    if magic == SLB2_MAGIC:
        print("### SLB2/BLS-Container ###")
        c = SLB2(p).parse()
        print("Version %d, Flags 0x%X, %d Eintraege, %d Sektoren, Daten ab 0x%X"
              % (c.version, c.flags, c.file_count, c.block_count, c.data_start))
        if c.prefix.strip(b"\0"):
            print("Zwischenraum 0x%X-0x%X: %s"
                  % (32 + 48 * c.file_count, c.data_start, c.prefix[:32].hex(" ")))
        print()
        c.print_table()
        print()
        print("Hinweis: PS4UPDATE.PUP enthaelt PS4UPDATE1/2.PUP. Diese sind die")
        print("eigentlichen Firmware-Fragmente -> 'pup info' darauf anwenden.")
    elif magic == PUP_MAGIC:
        print("### PUP-Fragment ###")
        try:
            PUP(p, keys_or_empty(a.keys)).parse().print_info()
        except NeedHeaderKey as e:
            die(str(e) + "\n    -> 'decrypt-header --key ... --iv ...' oder .dec von der Konsole")
    else:
        img_info(p)


def cmd_slb(a):
    c = SLB2(a.file).parse()
    if a.action == "list":
        c.print_table()
    else:
        c.extract(a.out)


def cmd_slb_build(a):
    SLB2.build(a.dir, a.out, version=a.version, flags=a.flags)


def cmd_pup(a):
    p = PUP(a.file, keys_or_empty(a.keys))
    try:
        p.parse()
    except NeedHeaderKey as e:
        die(str(e))
    if a.action == "info":
        p.print_info()
    elif a.action == "verify":
        bad = p.verify()
        ok("fertig, %d Abweichungen" % bad)
    else:
        only = None
        if a.only:
            only = {int(x, 0) for x in a.only.split(",")}
        p.extract(a.out, only, decrypt=not a.no_decrypt)


def cmd_decrypt_header(a):
    data = bytearray(Path(a.file).read_bytes())
    if data[:4] != PUP_MAGIC:
        die("kein PUP-Fragment")
    hsize, msize = struct.unpack_from("<HH", data, 0x0C)
    total = hsize + msize
    key, iv = parse_key(a.key), parse_key(a.iv)
    data[0x20:total] = AES(key).cbc_decrypt(bytes(data[0x20:total]), iv)
    data[0x0A] |= 1
    Path(a.out).write_bytes(bytes(data))
    ok("Header entschluesselt -> %s" % a.out)


def cmd_hex(a):
    data = Path(a.file).read_bytes()
    off = int(a.offset, 0)
    ln = int(a.length, 0)
    print(hexdump(data[off:off + ln], off))


def cmd_patch(a):
    p = Path(a.file)
    data = bytearray(p.read_bytes())
    off = int(a.offset, 0)
    new = bytes.fromhex(a.hex.replace(" ", ""))
    if a.backup:
        Path(str(p) + ".bak").write_bytes(bytes(data))
    old = bytes(data[off:off + len(new)])
    data[off:off + len(new)] = new
    p.write_bytes(bytes(data))
    ok("0x%X: %s -> %s" % (off, old.hex(" "), new.hex(" ")))


def cmd_find(a):
    data = Path(a.file).read_bytes()
    pat = bytes.fromhex(a.pattern.replace(" ", "")) if a.hexpat else a.pattern.encode("latin-1")
    hits, start = 0, 0
    while True:
        i = data.find(pat, start)
        if i < 0:
            break
        print("0x%08X  %s" % (i, hexdump(data[max(0, i - 8):i + len(pat) + 8],
                                        max(0, i - 8)).replace("\n", "\n          ")))
        hits += 1
        if not a.all:
            break
        start = i + 1
    ok("%d Treffer" % hits)


def cmd_strings(a):
    data = Path(a.file).read_bytes()
    n = 0
    for m in re.finditer(rb"[\x20-\x7E]{%d,}" % a.min, data):
        print("0x%08X  %s" % (m.start(), m.group().decode("latin-1")))
        n += 1
    ok("%d Strings" % n)


def cmd_entropy(a):
    data = Path(a.file).read_bytes()
    win = int(a.window, 0)
    for off in range(0, len(data), win):
        e = entropy(data[off:off + win])
        bar = "#" * int(e / 8 * 40)
        print("%08X  %.2f  %s" % (off, e, bar))


def cmd_diff(a):
    x, y = Path(a.file1).read_bytes(), Path(a.file2).read_bytes()
    n = min(len(x), len(y))
    print("A=%d B=%d Bytes, vergleiche %d" % (len(x), len(y), n))
    i, regions = 0, []
    while i < n:
        if x[i] != y[i]:
            j = i
            while j < n and x[j] != y[j]:
                j += 1
            regions.append((i, j))
            i = j
        else:
            i += 1
    for s, e in regions[:a.limit]:
        print("0x%08X  %d Byte  A=%s  B=%s"
              % (s, e - s, x[s:min(e, s + 16)].hex(" "), y[s:min(e, s + 16)].hex(" ")))
    ok("%d Diff-Regionen" % len(regions))


def cmd_crypto(a):
    data = Path(a.file).read_bytes()
    if a.op == "xor":
        key = parse_key(a.key)
        out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    else:
        c = AES(parse_key(a.key))
        if a.mode == "cbc":
            iv = parse_key(a.iv)
            out = c.cbc_decrypt(data, iv, unpad=a.unpad) if a.op == "dec" else c.cbc_encrypt(data, iv)
        else:
            out = c.ecb_decrypt(data) if a.op == "dec" else c.ecb_encrypt(data)
    Path(a.out).write_bytes(out)
    ok("%s -> %s (%s)" % (a.op, a.out, human(len(out))))


def cmd_img(a):
    if a.action == "info":
        img_info(a.file)
    elif a.action == "carve":
        carve(a.file)
    else:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        seven = shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")
        if not seven:
            warn("7-Zip nicht gefunden. Nutze den Python-Parser:")
            print("  python ps4fwkit_ext.py fs extract %s -o %s" % (a.file, out))
            return
        r = subprocess.run([seven, "x", "-y", "-o" + str(out), a.file])
        ok("7z Exitcode %d -> %s" % (r.returncode, out))


def cmd_self(a):
    self_info(a.file)


def cmd_exploit(a):
    rows = [(k, v) for k, v in IDS.items()
            if v["rank"] in ("kritisch", "hoch")
            and (not a.filter or a.filter.lower() in (v["name"] + v["desc"] + v["exploit"]).lower())]
    rows.sort(key=lambda kv: RANK_ORDER[kv[1]["rank"]])
    for k, v in rows:
        print("0x%03X  %-30s [%s]" % (k, v["name"], v["rank"]))
        print("       Zweck  : %s" % v["desc"])
        print("       Angriff: %s" % v["exploit"])
        print("       Krypto : %s" % v["crypto"])
        print()


KEYS_TEMPLATE = {
    "_comment": "pup_header_key/iv sind pro Konsole unterschiedlich. Aus ps4-cfw-toolkit keys.json.",
    "pup_header_key": "",
    "pup_header_iv": "",
}


def load_keys(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def keys_or_empty(path):
    if not path:
        return {}
    if not Path(path).exists():
        warn("Key-Datei %s fehlt - arbeite ohne Keys" % path)
        return {}
    try:
        return load_keys(path)
    except (json.JSONDecodeError, OSError) as e:
        warn("Key-Datei unlesbar (%s) - arbeite ohne Keys" % e)
        return {}


def cmd_keys(a):
    if a.action == "init":
        Path(a.out).write_text(json.dumps(KEYS_TEMPLATE, indent=2), encoding="utf-8")
        ok("Template -> %s" % a.out)
    else:
        k = load_keys(a.file)
        for name, val in k.items():
            if name.startswith("_"):
                continue
            print("%-24s %s" % (name, (val[:32] + "...") if len(val) > 32 else (val or "<leer>")))


# ------------------------------------------------------------------------ CLI

def main():
    ap = argparse.ArgumentParser(
        prog="ps4fwkit",
        description="All-in-One PS4-Firmware-Toolkit (PUP/SLB2/SLB/IMG/SELF/Hex/Krypto)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Beispiele:\n"
               "  ps4fwkit.py info PS4UPDATE.PUP\n"
               "  ps4fwkit.py info <verzeichnis>\n"
               "  ps4fwkit.py slb extract PS4UPDATE.PUP -o dump\n"
               "  ps4fwkit.py pup info dump/00_PS4UPDATE1.PUP --keys keys.json\n"
               "  ps4fwkit.py img info seg/06_system_fs_image.img\n")
    ap.add_argument("--version", action="version", version="ps4fwkit " + VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="Datei oder Verzeichnis identifizieren")
    p.add_argument("file")
    p.add_argument("--keys")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("scan", help="Verzeichnis rekursiv identifizieren")
    p.add_argument("file")
    p.add_argument("--keys")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("slb", help="SLB2/BLS-Container zerlegen")
    p.add_argument("action", choices=["list", "extract"])
    p.add_argument("file")
    p.add_argument("-o", "--out", default="slb_out")
    p.set_defaults(func=cmd_slb)

    p = sub.add_parser("slb-build", help="SLB2-Container aus Verzeichnis bauen")
    p.add_argument("dir")
    p.add_argument("out")
    p.add_argument("--version", type=int, default=1)
    p.add_argument("--flags", type=lambda s: int(s, 0), default=0)
    p.set_defaults(func=cmd_slb_build)

    p = sub.add_parser("pup", help="PUP-Fragment parsen/entpacken/verifizieren")
    p.add_argument("action", choices=["info", "extract", "verify"])
    p.add_argument("file")
    p.add_argument("-o", "--out", default="pup_out")
    p.add_argument("--keys")
    p.add_argument("--only", help="nur diese IDs, z.B. 5,6,7")
    p.add_argument("--no-decrypt", action="store_true")
    p.set_defaults(func=cmd_pup)

    p = sub.add_parser("decrypt-header", help="PUP-Header mit Key/IV entschluesseln")
    p.add_argument("file")
    p.add_argument("--key", required=True)
    p.add_argument("--iv", required=True)
    p.add_argument("-o", "--out", required=True)
    p.set_defaults(func=cmd_decrypt_header)

    p = sub.add_parser("hex", help="Hexdump")
    p.add_argument("file")
    p.add_argument("--offset", default="0")
    p.add_argument("--length", default="512")
    p.set_defaults(func=cmd_hex)

    p = sub.add_parser("patch", help="Bytes an Offset schreiben")
    p.add_argument("file")
    p.add_argument("--offset", required=True)
    p.add_argument("--hex", required=True)
    p.add_argument("--no-backup", dest="backup", action="store_false", default=True)
    p.set_defaults(func=cmd_patch)

    p = sub.add_parser("find", help="Byte-Muster oder String suchen")
    p.add_argument("file")
    p.add_argument("--pattern", required=True)
    p.add_argument("--hex", dest="hexpat", action="store_true")
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("strings", help="Strings extrahieren")
    p.add_argument("file")
    p.add_argument("--min", type=int, default=6)
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("entropy", help="Entropie-Karte")
    p.add_argument("file")
    p.add_argument("--window", default="4096")
    p.set_defaults(func=cmd_entropy)

    p = sub.add_parser("diff", help="Zwei Dateien vergleichen")
    p.add_argument("file1")
    p.add_argument("file2")
    p.add_argument("--limit", type=int, default=200)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("crypto", help="AES/XOR ver- und entschluesseln")
    p.add_argument("op", choices=["enc", "dec", "xor"])
    p.add_argument("file")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--iv", default="00" * 16)
    p.add_argument("--mode", choices=["cbc", "ecb"], default="cbc")
    p.add_argument("--unpad", action="store_true")
    p.set_defaults(func=cmd_crypto)

    p = sub.add_parser("img", help="IMG-Dateien: Info, Carven, Entpacken")
    p.add_argument("action", choices=["info", "extract", "carve"])
    p.add_argument("file")
    p.add_argument("-o", "--out", default="img_out")
    p.set_defaults(func=cmd_img)

    p = sub.add_parser("self", help="SELF-Header anzeigen")
    p.add_argument("file")
    p.set_defaults(func=cmd_self)

    p = sub.add_parser("exploit", help="Angriffsflaeche pro Komponente")
    p.add_argument("--filter")
    p.set_defaults(func=cmd_exploit)

    p = sub.add_parser("keys", help="keys.json verwalten")
    p.add_argument("action", choices=["init", "show"])
    p.add_argument("file", nargs="?", default="keys.json")
    p.add_argument("-o", "--out", default="keys.json")
    p.set_defaults(func=cmd_keys)

    a = ap.parse_args()

    target = getattr(a, "file", None)
    if target and Path(target).is_dir() and a.cmd not in ("info", "scan"):
        print("[~] %s ist ein Verzeichnis - fuehre stattdessen einen Scan aus.\n" % target)
        scan_dir(target)
        print("\nDanach das gewuenschte Kommando auf eine konkrete Datei anwenden.")
        return

    try:
        a.func(a)
    except FileNotFoundError as e:
        die("Datei nicht gefunden: %s" % e.filename)
    except PermissionError as e:
        die("Kein Zugriff: %s (Datei gesperrt? Explorer-Vorschau/Virenscanner?)" % e.filename)
    except NeedHeaderKey as e:
        die(str(e))


if __name__ == "__main__":
    main()
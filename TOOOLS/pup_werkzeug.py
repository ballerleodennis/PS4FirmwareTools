#!/usr/bin/env python3
"""PS4-PUP-Werkzeug. Aufruf siehe pup.bat."""
import sys, os, json, zlib, hashlib

SLB_MAGIC = b"SLB2"
MAGIC = bytes.fromhex("4F153D1D")
SLB_HDR, SLB_ENT, ENT, DATA_START = 0x20, 0x30, 0x20, 0x400
FILES = {3: "wlan_firmware.bin", 5: "secure_modules.bin", 6: "fs/system.img",
         8: "fs/eap.img", 9: "fs/recovery.img", 11: "fs/preinst.img",
         12: "fs/system_ex.img", 34: "torus2_firmware.bin", 257: "eula.xml",
         512: "orbis_swu.elf", 514: "orbis_swu.self", 3337: "cp_firmware.bin"}
DEVS = {1: "sflash0s0x32b", 2: "sflash0s0x33", 3: "sflash0s0x38", 4: "sflash0s1.cryptx2b",
        5: "sflash0s1.cryptx3b", 7: "da0x2", 10: "sflash0s1.cryptx40", 3328: "sc_fw_update0",
        3329: "cd0", 3330: "da0", 3336: "sc_fw_update0"}


def u(b, o, n):
    return int.from_bytes(b[o:o + n], "little")


def load(p):
    with open(p, "rb") as f:
        return f.read()


def save(p, b):
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(p, "wb") as f:
        f.write(b)


def inflate(d):
    for w in (15, -15, 47):
        try:
            o = zlib.decompressobj(w)
            return o.decompress(d) + o.flush()
        except zlib.error:
            continue
    return None


def parse(b):
    if b[:4] != MAGIC:
        raise SystemExit("kein Fragment (magic %s)" % b[:4].hex())
    n = u(b, 0x18, 2)
    hs = u(b, 0x0C, 2) + u(b, 0x0E, 2)
    if not 0 < n <= 0x400 or SLB_HDR + n * ENT > len(b) or hs > len(b):
        raise SystemExit("Kopf unplausibel")
    if b[7] & 1:
        raise SystemExit("noch verschluesselt - erst auf der Konsole entschluesseln")
    return n, hs


def cmd_info(p):
    b = load(p)
    if b[:4] == SLB_MAGIC:
        n, sec = u(b, 0x0C, 4), u(b, 0x10, 4)
        print("SLB2 version %d eintraege %d sektoren %d datei %d" % (u(b, 4, 4), n, sec, len(b)))
        print("recovery-marker: %s" % ("vorhanden" if any(b[0x200:0x280]) else "fehlt"))
        for i in range(n):
            r = b[SLB_HDR + i * SLB_ENT: SLB_HDR + (i + 1) * SLB_ENT]
            print("  [%d] 0x%X %d %s" % (i, u(r, 0, 4) * 512, u(r, 4, 4),
                                         r[0x10:0x30].split(b"\0")[0].decode("latin1")))
        return
    n, hs = parse(b)
    print("Fragment version %d mode %d endian %d flags 0x%X content %d" % (b[4], b[5], b[6], b[7], b[8]))
    print("header 0x%X meta 0x%X blaetter %d file_size 0x%X (%d)"
          % (hs, u(b, 0x0E, 2), n, u(b, 0x10, 8), u(b, 0x10, 8)))


def cmd_list(p):
    b = load(p)
    n, hs = parse(b)
    for i in range(n):
        f = u(b, SLB_HDR + i * ENT, 4)
        sid, sp = f >> 20, f & 0xF0000000
        tag = ("signatur" if sp == 0xE0000000 else "wasserzeichen" if sp == 0xF0000000
               else "tabelle" if f & 1 else "blockiert" if f & 0x800
               else "komprimiert" if f & 0x8 else "roh")
        print("  [%2d] id 0x%03X %-14s flags %08X off 0x%X csize %d usize %d"
              % (i, sid, tag, f, u(b, SLB_HDR + i * ENT + 8, 8),
                 u(b, SLB_HDR + i * ENT + 0x10, 8), u(b, SLB_HDR + i * ENT + 0x18, 8)))


def cmd_split(p, outdir):
    b = load(p)
    if b[:4] != SLB_MAGIC:
        raise SystemExit("kein SLB2-Container")
    n = u(b, 0x0C, 4)
    save(os.path.join(outdir, "_slbheader.bin"), b[:DATA_START])
    man = []
    for i in range(n):
        r = b[SLB_HDR + i * SLB_ENT: SLB_HDR + (i + 1) * SLB_ENT]
        off, ln = u(r, 0, 4) * 512, u(r, 4, 4)
        name = r[0x10:0x30].split(b"\0")[0].decode("latin1") or "eintrag%d" % i
        save(os.path.join(outdir, name), b[off:off + ln])
        man.append({"name": name})
        print("  [%d] %s %d bytes sha256 %s" % (i, name, ln, hashlib.sha256(b[off:off + ln]).hexdigest()[:16]))
    save(os.path.join(outdir, "_slb.json"), json.dumps({"entries": man}).encode())


def cmd_extract(p, outdir):
    b = load(p)
    n, hs = parse(b)
    save(os.path.join(outdir, "_meta.bin"), b[SLB_HDR + n * ENT:hs])
    rec = {"header": b[:SLB_HDR].hex(), "blobs": []}
    tables = {u(b, SLB_HDR + j * ENT, 4) >> 20: j
              for j in range(n) if u(b, SLB_HDR + j * ENT, 4) & 1}

    for i in range(n):
        e = SLB_HDR + i * ENT
        f, off = u(b, e, 4), u(b, e + 8, 8)
        cs, us = u(b, e + 0x10, 8), u(b, e + 0x18, 8)
        sid, sp = f >> 20, f & 0xF0000000
        if sp:
            print("  [%2d] uebersprungen (signatur/wasserzeichen)" % i)
            rec["blobs"].append({"flags": f, "skip": 1})
            continue
        if f & 1:
            print("  [%2d] id 0x%03X tabelle" % (i, sid))
            rec["blobs"].append({"flags": f, "skip": 1})
            continue
        if off + cs > len(b):
            print("  [%2d] ragt ueber das dateiende" % i)
            rec["blobs"].append({"flags": f, "skip": 1})
            continue

        if f & 0x800:
            j = tables.get(i)
            if j is None:
                raise SystemExit("keine Tabelle fuer Blatt %d" % i)
            te = SLB_HDR + j * ENT
            to, ts, tus = u(b, te + 8, 8), u(b, te + 0x10, 8), u(b, te + 0x18, 8)
            tab = b[to:to + ts]
            if u(b, te, 4) & 8:
                tab = inflate(tab)
            bs = 1 << (((f & 0xF000) >> 12) + 12)
            nb = (us + bs - 1) // bs
            tail = us % bs or bs
            inf = tab[32 * nb:]
            parts, pos, rem = [], off, cs
            for k in range(nb):
                bo, bz = u(inf, k * 8, 4), u(inf, k * 8 + 4, 4)
                if bo:
                    pos = off + bo
                raw = b[pos:pos + bz]
                pos += bz
                if (bz & ~0xF) != bs and (k != nb - 1 or tail != bz):
                    raw = inflate(raw[:bz - (bz & 0xF)])
                parts.append(raw)
                rem -= bz
            data = b"".join(parts)
        else:
            data = b[off:off + cs]
            if f & 0x8:
                d = inflate(data)
                if d is None:
                    print("  [%2d] entpacken fehlgeschlagen, Rohschnitt" % i)
                else:
                    data = d

        if sid in FILES:
            name = "%02d_%s" % (i, FILES[sid].replace("/", "_"))
        elif sid in DEVS:
            name = "%02d_dev_%s.bin" % (i, DEVS[sid])
        else:
            name = "%02d_id%03X.bin" % (i, sid)
        save(os.path.join(outdir, name), data)
        rec["blobs"].append({"flags": f, "file": name, "usize": len(data)})
        print("  [%2d] -> %s (%d bytes)" % (i, name, len(data)))
    save(os.path.join(outdir, "_frag.json"), json.dumps(rec).encode())


def cmd_pack(d, outp):
    rec = json.loads(load(os.path.join(d, "_frag.json")))
    mp = os.path.join(d, "_meta.bin")
    meta = load(mp) if os.path.exists(mp) else b""
    hdr = bytearray(bytes.fromhex(rec["header"]))
    base = SLB_HDR + len(rec["blobs"]) * ENT
    tab, body, blobs = bytearray(), bytearray(), []

    for i, r in enumerate(rec["blobs"]):
        f = r["flags"]
        if r.get("skip"):
            blobs.append((f, 0, 0, 0))
            continue
        raw = load(os.path.join(d, r["file"]))
        us = len(raw)
        if f & 0x8:
            raw = zlib.compress(raw, 9)
        off = base + len(body)
        body += raw
        while len(body) % 0x10:
            body += b"\0"
        blobs.append((f, off, len(raw), us))

    hs = base + len(meta)
    hdr[0x0C:0x0E] = (hs & 0xFFFF).to_bytes(2, "little")
    hdr[0x0E:0x10] = ((len(meta) - 0x30) & 0xFFFF).to_bytes(2, "little")
    hdr[0x10:0x18] = (hs + len(body)).to_bytes(8, "little")
    hdr[0x18:0x1A] = len(blobs).to_bytes(2, "little")
    for f, off, cs, us in blobs:
        tab += f.to_bytes(4, "little") + b"\0" * 4
        tab += off.to_bytes(8, "little") + cs.to_bytes(8, "little") + us.to_bytes(8, "little")
    save(outp, bytes(hdr) + bytes(tab) + meta + bytes(body))
    print("fertig: %s (%d Blaetter)" % (outp, len(blobs)))


def cmd_merge(d, outp):
    man = json.loads(load(os.path.join(d, "_slb.json")))
    tpl = bytearray(load(os.path.join(d, "_slbheader.bin")).ljust(DATA_START, b"\0"))
    tab, body, pos = bytearray(), bytearray(), DATA_START
    for e in man["entries"]:
        raw = load(os.path.join(d, e["name"]))
        pos = (pos + 0x1FF) & ~0x1FF
        body += b"\0" * (pos - (DATA_START + len(body)))
        tab += (pos // 512).to_bytes(4, "little") + len(raw).to_bytes(4, "little")
        tab += b"\0" * 8 + e["name"].encode("latin1")[:31].ljust(0x20, b"\0")
        body += raw
        pos += len(raw)
    out = bytearray(tpl[:SLB_HDR]) + tab
    out += b"\0" * (DATA_START - len(out))
    out += body
    out[0x0C:0x10] = len(man["entries"]).to_bytes(4, "little")
    out[0x10:0x14] = ((len(out) + 0x1FF) // 0x200).to_bytes(4, "little")
    save(outp, bytes(out))
    print("fertig: %s" % outp)


def main(a):
    m = a[1]
    if m == "info":
        cmd_info(a[2])
    elif m == "list":
        cmd_list(a[2])
    elif m == "split":
        cmd_split(a[2], a[3])
    elif m == "extract":
        cmd_extract(a[2], a[3])
    elif m == "pack":
        cmd_pack(a[2], a[3])
    elif m == "merge":
        cmd_merge(a[2], a[3])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
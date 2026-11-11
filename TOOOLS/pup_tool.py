#!/usr/bin/env python3
"""Werkzeug fuer PS4-PUP-Container (SLB2) und deren Fragmente.

  info    <datei>            Struktur anzeigen
  split   <datei> <ordner>   Container in Fragmente trennen
  list    <datei>            Blatt-Tabelle eines Fragments anzeigen
  extract <datei> <ordner>   Blaetter entpacken (nur entschluesselt)
  pack    <ordner> <datei>   Fragment aus Ordner neu bauen
  merge   <ordner> <datei>   Container aus Fragmenten neu bauen
"""
import sys, os, json, zlib, hashlib

SLB_MAGIC = b"SLB2"
FRAG_MAGIC = bytes.fromhex("4F153D1D")
SLB_HDR, SLB_ENT, BLOB, DATA_START = 0x20, 0x30, 0x20, 0x400
IDS = {
    0x1: "emc_ipl", 0x2: "eap_kbl", 0x3: "torus2_fw", 0x4: "sam_ipl",
    0x5: "coreos", 0x6: "system_exfat", 0x7: "eap_kernel", 0x8: "eap_vsh",
    0x9: "preinst", 0xB: "preinst2", 0xC: "system_ex_exfat", 0x20: "emc_ipl",
    0x21: "eap_kbl", 0x22: "torus2_fw", 0x23: "sam_ipl", 0x101: "eula.xml",
    0x200: "orbis_swu.elf", 0x202: "orbis_swu.self", 0xD01: "bd_firm",
    0xD02: "sata_bridge_fw", 0xD09: "cp_fw_kernel",
}


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


def blob_table(b):
    if b[:4] != FRAG_MAGIC:
        raise SystemExit("kein PUP-Fragment (magic %s)" % b[:4].hex())
    n = u(b, 0x18, 2)
    hs = u(b, 0x0C, 2) + u(b, 0x0E, 2)
    if not 0 < n <= 0x400 or SLB_HDR + n * BLOB > len(b):
        raise SystemExit("Blatt-Tabelle unplausibel (%d)" % n)
    return n, hs


def cmd_info(p):
    b = load(p)
    if b[:4] == SLB_MAGIC:
        n, sec = u(b, 0x0C, 4), u(b, 0x10, 4)
        print("SLB2 version %d flags 0x%X eintraege %d sektoren %d (0x%X bytes) datei %d"
              % (u(b, 4, 4), u(b, 8, 4), n, sec, sec * 512, len(b)))
        print("recovery-marker 0x200-0x280: %s"
              % ("vorhanden" if any(b[0x200:0x280]) else "fehlt"))
        for i in range(n):
            r = b[SLB_HDR + i * SLB_ENT: SLB_HDR + (i + 1) * SLB_ENT]
            off, ln = u(r, 0, 4) * 512, u(r, 4, 4)
            print("  [%d] 0x%X..0x%X %d %s"
                  % (i, off, off + ln, ln, r[0x10:0x30].split(b"\0")[0].decode("latin1")))
    elif b[:4] == FRAG_MAGIC:
        hs = u(b, 0x0C, 2) + u(b, 0x0E, 2)
        print("Fragment version %d mode %d endian %d flags 0x%X content %d header 0x%X meta 0x%X"
              % (b[4], b[5], b[6], b[7], b[8], hs, u(b, 0x0E, 2)))
        print("kopf %s" % ("entschluesselt" if not b[7] & 1 else "verschluesselt"))
    else:
        raise SystemExit("unbekannter Typ (magic %s)" % b[:4].hex())


def cmd_split(p, outdir):
    b = load(p)
    if b[:4] != SLB_MAGIC:
        raise SystemExit("kein SLB2-Container")
    n = u(b, 0x0C, 4)
    if not 0 < n <= 10:
        raise SystemExit("Eintragszahl unplausibel (%d)" % n)
    save(os.path.join(outdir, "_slbheader.bin"), b[:DATA_START])
    ent = []
    for i in range(n):
        r = b[SLB_HDR + i * SLB_ENT: SLB_HDR + (i + 1) * SLB_ENT]
        off, ln = u(r, 0, 4) * 512, u(r, 4, 4)
        name = r[0x10:0x30].split(b"\0")[0].decode("latin1") or "eintrag%d" % i
        if off + ln > len(b):
            print("  [%d] %s laeuft ueber das dateiende" % (i, name))
        save(os.path.join(outdir, name), b[off:off + ln])
        ent.append({"name": name, "size": ln})
        print("  [%d] %s 0x%X..0x%X %d sha256 %s"
              % (i, name, off, off + ln, ln, hashlib.sha256(b[off:off + ln]).hexdigest()[:16]))
    save(os.path.join(outdir, "_slb.json"), json.dumps({"entries": ent}, indent=1).encode())
    print("fertig: %d Fragmente + Vorlage in %s" % (n, outdir))


def cmd_list(p):
    b = load(p)
    n, hs = blob_table(b)
    print("blaetter %d header 0x%X" % (n, hs))
    for i in range(n):
        e = b[SLB_HDR + i * BLOB: SLB_HDR + (i + 1) * BLOB]
        f = u(e, 0, 4)
        sid, sp = f >> 20, f & 0xF0000000
        tag = ("zusatzsignatur" if sp == 0xE0000000 else "wasserzeichen" if sp == 0xF0000000
               else "blockiert" if f & 0x800 else "komprimiert" if f & 0x8 else "roh")
        print("  [%2d] id 0x%03X %-24s flags %08X off 0x%X csize %d usize %d"
              % (i, sid, IDS.get(sid, "?"), f, u(e, 8, 8), u(e, 0x10, 8), u(e, 0x18, 8)))


def cmd_extract(p, outdir):
    b = load(p)
    n, hs = blob_table(b)
    if b[7] & 1:
        raise SystemExit("Fragment ist noch verschluesselt, erst auf der Konsole entschluesseln")
    save(os.path.join(outdir, "_meta.bin"), b[SLB_HDR + n * BLOB:hs])
    rec = {"header": b[:SLB_HDR].hex(), "blobs": []}
    for i in range(n):
        e = b[SLB_HDR + i * BLOB: SLB_HDR + (i + 1) * BLOB]
        f, off = u(e, 0, 4), u(e, 8, 8)
        cs, us = u(e, 0x10, 8), u(e, 0x18, 8)
        sid, sp = f >> 20, f & 0xF0000000
        if sp:
            print("  [%2d] %s" % (i, "uebersprungen (signatur/wasserzeichen)"))
            rec["blobs"].append({"flags": f, "skip": 1})
            continue
        if off + cs > len(b):
            print("  [%2d] laeuft ueber das dateiende" % i)
            rec["blobs"].append({"flags": f, "skip": 1})
            continue
        data = b[off:off + cs]
        if f & 0x800:
            t = next((j for j in range(n) if (u(b, SLB_HDR + j * BLOB, 4) & 1)
                      and (u(b, SLB_HDR + j * BLOB, 4) >> 20) == i), None)
            if t is None:
                print("  [%2d] keine Tabelle, Rohschnitt" % i)
            else:
                to, tl = u(b, SLB_HDR + t * BLOB + 8, 8), u(b, SLB_HDR + t * BLOB + 0x10, 8)
                tab = b[to:to + tl]
                bs = 1 << (((f & 0xF000) >> 12) + 12)
                nb = (us + bs - 1) // bs
                inf = tab[32 * nb:]
                chunks, pos = [], off
                for k in range(nb):
                    bo, bz = u(inf, k * 8, 4), u(inf, k * 8 + 4, 4)
                    st = off + bo if bo else pos
                    chunks.append(b[st:st + bz])
                    pos = st + bz
                data = b"".join(chunks)
        if f & 0x8:
            out = inflate(data)
            if out is None:
                print("  [%2d] entpacken fehlgeschlagen, Rohschnitt" % i)
            else:
                data = out
        name = "%02d_%s%s" % (i, IDS.get(sid, "id%03X" % sid), ".bin")
        save(os.path.join(outdir, name), data)
        rec["blobs"].append({"flags": f, "file": name, "usize": len(data)})
        print("  [%2d] -> %s (%d bytes)" % (i, name, len(data)))
    save(os.path.join(outdir, "_frag.json"), json.dumps(rec, indent=1).encode())
    print("fertig: %s" % outdir)


def cmd_pack(d, outp):
    rec = json.loads(load(os.path.join(d, "_frag.json")))
    meta = load(os.path.join(d, "_meta.bin")) if os.path.exists(os.path.join(d, "_meta.bin")) else b""
    hdr = bytearray(bytes.fromhex(rec["header"]))
    blobs, data = [], bytearray()
    base = SLB_HDR + len(rec["blobs"]) * BLOB
    for i, r in enumerate(rec["blobs"]):
        f = r["flags"]
        if r.get("skip"):
            blobs.append((f, 0, 0, 0))
            continue
        raw = load(os.path.join(d, r["file"]))
        us = len(raw)
        if f & 0x8:
            raw = zlib.compress(raw, 9)
        off = base + len(data)
        data += raw
        while len(data) % 0x10:
            data += b"\0"
        blobs.append((f, off, len(raw), us))
    hs = base + len(meta)
    hdr[0x0C:0x0E] = (hs & 0xFFFF).to_bytes(2, "little")
    hdr[0x0E:0x10] = ((len(meta) - 0x30) & 0xFFFF).to_bytes(2, "little")
    hdr[0x10:0x14] = (hs + len(data)).to_bytes(4, "little")
    hdr[0x18:0x1A] = len(blobs).to_bytes(2, "little")
    tab = bytearray()
    for f, off, cs, us in blobs:
        tab += f.to_bytes(4, "little") + b"\0" * 4 + off.to_bytes(8, "little")
        tab += cs.to_bytes(8, "little") + us.to_bytes(8, "little")
    save(outp, bytes(hdr) + bytes(tab) + meta + bytes(data))
    print("fertig: %s (%d Blaetter, %d bytes)" % (outp, len(blobs), hs + len(data)))


def cmd_merge(d, outp):
    man = json.loads(load(os.path.join(d, "_slb.json")))
    tpl = bytearray(load(os.path.join(d, "_slbheader.bin")))
    if len(tpl) < DATA_START:
        tpl = bytearray(tpl.ljust(DATA_START, b"\0"))
    pos, tab, body = DATA_START, bytearray(), bytearray()
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
    print("fertig: %s (%d Eintraege, %d bytes)" % (outp, len(man["entries"]), len(out)))


def main(a):
    if len(a) < 3:
        print(__doc__)
        return 2
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
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
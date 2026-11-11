#!/usr/bin/env python3
"""Entpackt ein bereits entschluesseltes PS4-PUP-Fragment."""
import sys, os, zlib

MAGIC = bytes.fromhex("4F153D1D")
BLOB = 0x20
IDS = {
    0x1: "emc_ipl.slb", 0x2: "eap_kbl.slb", 0x3: "torus2_fw.slb", 0x4: "sam_ipl.slb",
    0x5: "coreos.slb", 0x6: "system_exfat.img", 0x7: "eap_kernel.slb",
    0x8: "eap_vsh_fat16.img", 0x9: "preinst_fat32.img", 0xB: "preinst2_fat32.img",
    0xC: "system_ex_exfat.img", 0x20: "emc_ipl.slb", 0x21: "eap_kbl.slb",
    0x22: "torus2_fw.slb", 0x23: "sam_ipl.slb", 0x101: "eula.xml",
    0x200: "orbis_swu.elf", 0x202: "orbis_swu.self", 0xD01: "bd_firm.slb",
    0xD02: "sata_bridge_fw.slb", 0xD09: "cp_fw_kernel.slb",
}


def inflate(data):
    for wbits in (15, -15, 47):
        try:
            return zlib.decompressobj(wbits).decompress(data) + zlib.decompressobj(wbits).flush()
        except zlib.error:
            continue
    return None


def main(argv):
    if len(argv) != 3:
        print("usage: pup_extract.py <PSUUPDATE#.PUP.dec> <outdir>")
        return 2
    src, outdir = argv[1], argv[2]
    blob = open(src, "rb").read()
    if blob[:4] != MAGIC:
        print("kein entschluesseltes Fragment (magic %s)" % blob[:4].hex())
        return 1

    count = int.from_bytes(blob[0x18:0x1A], "little")
    hsize = int.from_bytes(blob[0x0C:0x0E], "little") + int.from_bytes(blob[0x0E:0x10], "little")
    print("blaetter %d header 0x%X dateigroesse 0x%X (%d)"
          % (count, hsize, int.from_bytes(blob[0x10:0x14], "little"), len(blob)))
    if 0x20 + count * BLOB > len(blob):
        print("blaettertabelle passt nicht in die datei")
        return 1

    os.makedirs(outdir, exist_ok=True)
    for i in range(count):
        b = blob[0x20 + i * BLOB: 0x20 + (i + 1) * BLOB]
        flags = int.from_bytes(b[0x00:0x04], "little")
        off = int.from_bytes(b[0x08:0x10], "little")
        csize = int.from_bytes(b[0x10:0x18], "little")
        usize = int.from_bytes(b[0x18:0x20], "little")
        sid = flags >> 20
        special = flags & 0xF0000000
        name = "%02d_%s" % (i, IDS.get(sid, "id%03X" % sid))
        tag = ("zusatzsignatur" if special == 0xE0000000 else
               "wasserzeichen" if special == 0xF0000000 else
               "blockiert" if flags & 0x800 else "komprimiert" if flags & 0x8 else "roh")
        print("[%2d] %-24s flags %08X off 0x%X csize %d usize %d"
              % (i, name, flags, off, csize, usize))

        if special:
            continue
        if off + csize > len(blob):
            print("     laeuft ueber das dateiende")
            continue

        if flags & 0x800:
            tinfo = next((j for j in range(count) if (int.from_bytes(
                blob[0x20 + j * BLOB:0x24 + j * BLOB], "little") & 1)
                and (int.from_bytes(blob[0x20 + j * BLOB:0x24 + j * BLOB], "little") >> 20) == i), None)
            if tinfo is None:
                print("     keine tabelle gefunden, rohschnitt")
                data = blob[off:off + csize]
            else:
                toff = int.from_bytes(blob[0x28 + tinfo * BLOB:0x30 + tinfo * BLOB], "little")
                tlen = int.from_bytes(blob[0x30 + tinfo * BLOB:0x38 + tinfo * BLOB], "little")
                table = blob[toff:toff + tlen]
                bsize = 1 << (((flags & 0xF000) >> 12) + 12)
                nblocks = (usize + bsize - 1) // bsize
                infos = table[32 * nblocks:]
                chunks, pos = [], off
                for k in range(nblocks):
                    bo = int.from_bytes(infos[k * 8:k * 8 + 4], "little")
                    bs = int.from_bytes(infos[k * 8 + 4:k * 8 + 8], "little")
                    start = off + bo if bo else pos
                    chunks.append(blob[start:start + bs])
                    pos = start + bs
                data = b"".join(chunks)

        else:
            data = blob[off:off + csize]

        if flags & 0x8:
            out = inflate(data)
            if out is None:
                print("     entpacken fehlgeschlagen, rohschnitt wird geschrieben")
                open(os.path.join(outdir, name + ".bin"), "wb").write(data)
                continue
            data = out
            if usize and len(data) != usize:
                print("     groesse %d statt %d" % (len(data), usize))
        open(os.path.join(outdir, name), "wb").write(data)
        print("     -> %s (%d bytes)" % (name, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

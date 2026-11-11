#!/usr/bin/env python3
# pup_list.py -- liest PS4-PUP-Kopf (Update + Recovery) und dumpt alle Blobs
import sys, os, struct, lzma, hashlib, mmap

BLOCK_DATA = 0x10000
BLOCK_HDR  = 0x100

def main(src, outdir):
    fsize = os.path.getsize(src)
    with open(src, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:

        print(f'Datei   : {src}')
        print(f'Groesse : {fsize} Bytes')
        print(f'Kopf    : {data[:0x20].hex(" ")}')

        if data[:4] != b'SCEUF':
            sys.exit(f'!! Magic {data[:4]!r} != b"SCEUF" -- keine PUP-Datei')

        ver, mode, endian, flags = struct.unpack_from('<4B', data, 4)
        content, product = struct.unpack_from('<2B', data, 8)
        hdr_size, meta_size, file_size = struct.unpack_from('<HHI', data, 0x0C)
        blob_count, flags2 = struct.unpack_from('<HH', data, 0x18)

        kind = {0x2: 'Recovery/Voll', 0x1: 'Update'}.get(content, f'0x{content:X}')
        print(f'\nTyp      : Content 0x{content:X} ({kind})  Product 0x{product:X}')
        print(f'Version 0x{ver:X}  Mode 0x{mode:X}  Endian 0x{endian:X}  Flags 0x{flags:X}')
        print(f'Header 0x{hdr_size:X}  Meta 0x{meta_size:X}  File-Size {file_size}')
        print(f'Blobs {blob_count}  Flags2 0x{flags2:X}')

        if file_size != fsize:
            sys.exit(f'!! Kopf nennt {file_size} Bytes, Datei hat {fsize} -- Abbruch/Fehlseite')
        if not 0 < blob_count <= 0x400 or hdr_size != 0x20:
            sys.exit('!! Kopf unplausibel, Datei beschaedigt')

        os.makedirs(outdir, exist_ok=True)
        enc = plain = 0

        for i in range(blob_count):
            bflags, boff, bsize, msize = struct.unpack_from('<QQQQ', data, hdr_size + i * 0x20)
            bid   = bflags >> 20
            comp  = bool(bflags & 0x8)
            blocked = bool(bflags & 0x800)

            line = (f'\n[{i:02d}] id=0x{bid:03X} flags=0x{bflags:X} '
                    f'comp={comp} blocked={blocked} off=0x{boff:X} size={bsize} mem={msize}')
            if blocked:
                line += f'  -> ~{bsize // BLOCK_DATA} Bloecke a {BLOCK_HDR}+{BLOCK_DATA}'
            print(line)

            if boff + bsize > fsize:
                print('  !! ragt ueber Dateiende, uebersprungen'); continue

            blob = data[boff:boff + bsize]

            if blob[:4] == b'SCEUF':
                print('  -> Klartext-Container (nicht verschluesselt)'); plain += 1
            else:
                print('  -> AES-verschluesselt'); enc += 1

            if comp:
                for fmt in (lzma.FORMAT_ALONE, lzma.FORMAT_AUTO):
                    try:
                        blob = lzma.decompress(blob, format=fmt)
                        print(f'  -> LZMA entpackt ({len(blob)} Bytes)'); break
                    except Exception:
                        pass
                else:
                    print('  -> LZMA fehlgeschlagen, Rohdaten')

            print(f'  sha256 {hashlib.sha256(blob).hexdigest()}')
            open(os.path.join(outdir, f'{i:02d}_0x{bid:03X}.bin'), 'wb').write(blob)

        print(f'\nFertig: {plain} Klartext, {enc} verschluesselt -> {outdir}')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'pup_out')

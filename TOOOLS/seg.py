#!/usr/bin/env python3
# Extrahiert ein block-basiertes PUP-Segment. Nur fuer ENTSCHLUESSELTE PUP-Fragmente.
import hashlib, struct, sys, zlib

MAGIC = 0x1D3D154F

def parse(path):
    f = open(path, 'rb')
    h = f.read(0x20)
    magic, = struct.unpack('<I', h[:4])
    if magic != MAGIC:
        sys.exit('Kein entschluesseltes PUP (Magic %08X).' % magic)
    entry_count, = struct.unpack('<H', h[0x14:0x16])
    entries = []
    for _ in range(entry_count):
        r = f.read(0x20)
        fl, = struct.unpack('<I', r[:4])
        off, cs, us = struct.unpack('<qqq', r[8:0x20])
        entries.append(dict(flags=fl, offset=off, csize=cs, usize=us,
                            id=fl >> 20, blocked=bool(fl & (1 << 11)),
                            compressed=bool(fl & (1 << 3)), info=bool(fl & 1)))
    return f, entries

def read_seg(f, e, size):
    f.seek(e['offset'])
    d = f.read(size)
    return zlib.decompress(d) if e['compressed'] else d

def main(pup, idx, out):
    f, entries = parse(pup)
    e = entries[idx]
    if not e['blocked'] or e['info']:
        sys.exit('Eintrag %d ist kein Datensegment mit Bloecken.' % idx)
    t = next((x for x in entries if x['info'] and x['id'] == idx), None)
    if t is None:
        sys.exit('Keine Blocktabelle fuer Eintrag %d.' % idx)

    bs = 1 << (((e['flags'] >> 12) & 0xF) + 12)
    n = -(-e['usize'] // bs)
    tail = e['usize'] % bs or bs
    tab = read_seg(f, t, t['usize'])
    digests = [tab[i*32:(i+1)*32] for i in range(n)]
    blocks = [struct.unpack('<II', tab[32*n + i*8: 32*n + i*8 + 8]) for i in range(n)]

    with open(out, 'wb') as o:
        o.truncate(e['usize'])
        for i, (boff, bsize) in enumerate(blocks):
            unpadded = (bsize & ~0xF) - (bsize & 0xF)
            readsize, comp = bs, False
            if unpadded != bs:
                readsize = bsize
                if i != n - 1 or tail != bsize:
                    readsize &= ~0xF
                    comp = True
            f.seek(e['offset'] + boff)
            data = f.read(readsize)
            if comp:
                want = min(bs, e['usize'] - i * bs)
                chunk = zlib.decompress(data[:readsize - (bsize & 0xF)])
                if len(chunk) != want:
                    sys.exit('Block %d: %d statt %d Bytes' % (i, len(chunk), want))
            else:
                chunk = data
            if hashlib.sha256(chunk).digest() != digests[i]:
                sys.exit('Block %d: Digest falsch (falsche Entschluesselung?)' % i)
            o.seek(i * bs)
            o.write(chunk)
    print('OK ->', out)

if __name__ == '__main__':
    main(sys.argv[1], int(sys.argv[2]), sys.argv[3])
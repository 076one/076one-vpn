#!/usr/bin/env python3
"""076one delta update patch (v1.8.7). Usage: mkpatch.py OLD.apk NEW.apk OUT.o76p

Format: b"O76P1\\n" + u64 newSize + 32-byte newSha256 + zlib(ops)
ops: b"C" u64 srcOffset u64 len   copy from the installed APK
     b"I" u64 len <bytes>          insert literal bytes
     b"E"                          end
Zip entry data (compressed bytes + descriptor) identical in OLD are copied, everything else
(changed entries, central directory, APK signing block) is inserted, so NEW is rebuilt byte for byte and its
signature still holds. The app checks the result's SHA-256 and signer and falls back to the full APK."""
import hashlib, struct, sys, zipfile, zlib

def regions(path):
    """[(start, end)] for each entry's local header, then its data (+ data descriptor), in file order"""
    data = open(path, 'rb').read()
    z = zipfile.ZipFile(path)
    infos = sorted(z.infolist(), key=lambda i: i.header_offset)
    out = []
    for n, i in enumerate(infos):
        s = i.header_offset
        assert data[s:s+4] == b'PK\x03\x04', path
        fnl, exl = struct.unpack('<HH', data[s+26:s+30])
        e = s + 30 + fnl + exl + i.compress_size
        if i.flag_bits & 8:
            e += 16 if data[e:e+4] == b'PK\x07\x08' else 12
        d = s + 30 + fnl + exl
        out.append((s, d))      # local header: small, changes with zipalign padding / timestamps -> inserted
        out.append((d, e))      # stored data (+ descriptor): copied when identical
    return data, out

def make(old, new, outp):
    od, orr = regions(old)
    nd, nr = regions(new)
    idx = {}
    for s, e in orr:
        idx.setdefault(hashlib.sha256(od[s:e]).digest(), s)
    ops = []  # ('C', off, len) | ('I', start, end) of nd
    pos = 0
    def ins(a, b):
        if b <= a: return
        if ops and ops[-1][0] == 'I' and ops[-1][2] == a: ops[-1] = ('I', ops[-1][1], b)
        else: ops.append(('I', a, b))
    for s, e in nr:
        ins(pos, s)
        h = hashlib.sha256(nd[s:e]).digest()
        if h in idx:
            off = idx[h]
            if ops and ops[-1][0] == 'C' and ops[-1][1] + ops[-1][2] == off: ops[-1] = ('C', ops[-1][1], ops[-1][2] + e - s)
            else: ops.append(('C', off, e - s))
        else:
            ins(s, e)
        pos = e
    ins(pos, len(nd))
    raw = bytearray()
    copied = 0
    for op in ops:
        if op[0] == 'C':
            raw += b'C' + struct.pack('<QQ', op[1], op[2]); copied += op[2]
        else:
            raw += b'I' + struct.pack('<Q', op[2] - op[1]) + nd[op[1]:op[2]]
    raw += b'E'
    body = b'O76P1\n' + struct.pack('<Q', len(nd)) + hashlib.sha256(nd).digest() + zlib.compress(bytes(raw), 9)
    open(outp, 'wb').write(body)
    # self-check: apply
    assert apply(od, body) == nd
    return len(body), copied

def apply(od, body):
    assert body[:6] == b'O76P1\n'
    size, = struct.unpack('<Q', body[6:14]); want = body[14:46]
    raw = zlib.decompress(body[46:]); p = 0; out = bytearray()
    while True:
        t = raw[p:p+1]; p += 1
        if t == b'C':
            off, n = struct.unpack('<QQ', raw[p:p+16]); p += 16; out += od[off:off+n]
        elif t == b'I':
            n, = struct.unpack('<Q', raw[p:p+8]); p += 8; out += raw[p:p+n]; p += n
        elif t == b'E': break
        else: raise ValueError('bad op')
    assert len(out) == size and hashlib.sha256(out).digest() == want
    return bytes(out)

if __name__ == '__main__':
    n, c = make(*sys.argv[1:4])
    print(f'{sys.argv[3]}: {n} bytes (copies {c} bytes from the old APK)')

import struct, sys

def imports(path):
    data = open(path, 'rb').read()
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[pe:pe+4] == b'PE\0\0'
    coff = pe + 4
    nsec = struct.unpack_from('<H', data, coff+2)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    ddir = opt + (112 if magic == 0x20b else 96)
    imp_rva, imp_size = struct.unpack_from('<II', data, ddir + 8)
    secs = opt + struct.unpack_from('<H', data, coff+16)[0]
    sections = []
    for i in range(nsec):
        o = secs + 40*i
        va = struct.unpack_from('<I', data, o+12)[0]
        vs = struct.unpack_from('<I', data, o+8)[0]
        raw = struct.unpack_from('<I', data, o+20)[0]
        sections.append((va, vs, raw))
    def off(rva):
        for va, vs, raw in sections:
            if va <= rva < va + vs:
                return raw + (rva - va)
        return None
    names = []
    o = off(imp_rva)
    while True:
        ilt, ts, fc, name_rva, iat = struct.unpack_from('<IIIII', data, o)
        if name_rva == 0:
            break
        n = off(name_rva)
        end = data.index(b'\0', n)
        names.append(data[n:end].decode())
        o += 20
    return names

for p in sys.argv[1:]:
    print(p, '->', ', '.join(imports(p)))

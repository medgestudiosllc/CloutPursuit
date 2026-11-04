#!/usr/bin/env python3
"""Independent checks for the hand-built APK: zip alignment, v2 signature,
binary manifest, resource table and DEX structure (with a disassembly)."""
import struct, zipfile, hashlib, zlib, sys

apk_path = sys.argv[1]
raw = open(apk_path, "rb").read()
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or c
results = []

# ---------------- zip + alignment
z = zipfile.ZipFile(apk_path)
results.append(ok(z.testzip() is None, "zip CRCs intact"))
for info in z.infolist():
    if info.compress_type == 0:
        nlen, xlen = struct.unpack_from("<HH", raw, info.header_offset + 26)
        data_off = info.header_offset + 30 + nlen + xlen
        results.append(ok(data_off % 4 == 0, f"stored entry {info.filename} 4-byte aligned (offset {data_off})"))
results.append(ok(z.getinfo("resources.arsc").compress_type == 0, "resources.arsc stored uncompressed (required for targetSdk 30+)"))

# ---------------- v2 signature
eocd = raw.rfind(b"PK\x05\x06")
cd_off, = struct.unpack_from("<I", raw, eocd + 16)
results.append(ok(raw[cd_off - 16:cd_off] == b"APK Sig Block 42", "APK signing block present before central directory"))
size_footer, = struct.unpack_from("<Q", raw, cd_off - 24)
blk_start = cd_off - size_footer - 8
size_header, = struct.unpack_from("<Q", raw, blk_start)
results.append(ok(size_header == size_footer, "signing block sizes match"))
pos, end, v2 = blk_start + 8, cd_off - 24, None
while pos < end:
    ln, = struct.unpack_from("<Q", raw, pos); pid, = struct.unpack_from("<I", raw, pos + 8)
    if pid == 0x7109871A: v2 = raw[pos + 12:pos + 8 + ln]
    pos += 8 + ln
results.append(ok(v2 is not None, "v2 signature scheme block found"))
def rd(b, p):
    n, = struct.unpack_from("<I", b, p); return b[p + 4:p + 4 + n], p + 4 + n
signers, _ = rd(v2, 0); signer, _ = rd(signers, 0)
signed_data, p = rd(signer, 0); sigs, p = rd(signer, p); pubkey, p = rd(signer, p)
digests, q = rd(signed_data, 0); certs, q = rd(signed_data, q)
d0, _ = rd(digests, 0); alg, = struct.unpack_from("<I", d0, 0); dig, _ = rd(d0, 4)
s0, _ = rd(sigs, 0); salg, = struct.unpack_from("<I", s0, 0); sig, _ = rd(s0, 4)
cert_der, _ = rd(certs, 0); cert_der, _ = rd(cert_der, 0) if False else (cert_der, 0)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
c0, _ = rd(certs, 0)
cert = x509.load_der_x509_certificate(c0)
pk = serialization.load_der_public_key(pubkey)
try:
    pk.verify(sig, signed_data, padding.PKCS1v15(), hashes.SHA256()); vs = True
except Exception as e:
    vs = False
results.append(ok(vs and alg == salg == 0x0103, "v2 RSA-SHA256 signature valid over signed data"))
results.append(ok(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == pubkey, "v2 certificate matches public key"))
def content_digest(sections):
    ch = []
    for s in sections:
        for i in range(0, len(s), 1 << 20):
            c = s[i:i + (1 << 20)]; ch.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(c)) + c).digest())
    return hashlib.sha256(b"\x5a" + struct.pack("<I", len(ch)) + b"".join(ch)).digest()
e = bytearray(raw[eocd:]); struct.pack_into("<I", e, 16, blk_start)
results.append(ok(content_digest([raw[:blk_start], raw[cd_off:eocd], bytes(e)]) == dig, "v2 content digest matches APK contents"))

# ---------------- AXML decode
def decode_pool(b, p):
    typ, hs, size = struct.unpack_from("<HHI", b, p); assert typ == 1
    cnt, sty, flags, sstart, _ = struct.unpack_from("<IIIII", b, p + 8)
    out = []
    for i in range(cnt):
        o, = struct.unpack_from("<I", b, p + 28 + 4 * i); q = p + sstart + o
        if flags & 0x100:
            ln = b[q + 1]; out.append(b[q + 2:q + 2 + ln].decode())
        else:
            ln, = struct.unpack_from("<H", b, q); out.append(b[q + 2:q + 2 + 2 * ln].decode("utf-16-le"))
    return out, p + size
m = z.read("AndroidManifest.xml")
typ, hs, size = struct.unpack_from("<HHI", m, 0)
results.append(ok(typ == 3 and size == len(m), "manifest is binary XML with correct size"))
strs, p = decode_pool(m, 8)
xml, depth, resmap = [], 0, []
while p < len(m):
    typ, hs, size = struct.unpack_from("<HHI", m, p)
    if typ == 0x0180: resmap = list(struct.unpack_from("<%dI" % ((size - 8) // 4), m, p + 8))
    if typ == 0x0102:
        ns, name, ast, asz, acnt = struct.unpack_from("<IIHHH", m, p + 16)
        attrs = []
        for i in range(acnt):
            a_ns, a_nm, a_raw, vsz, _, vt, vd = struct.unpack_from("<IIIHBBI", m, p + 16 + ast + i * asz)
            pre = "android:" if a_ns != 0xFFFFFFFF else ""
            rid = f"(0x{resmap[a_nm]:08x})" if a_nm < len(resmap) else ""
            val = strs[vd] if vt == 3 else (("true" if vd else "false") if vt == 0x12 else f"@0x{vd:08x}" if vt == 1 else hex(vd) if vt == 0x11 else str(vd))
            attrs.append(f'{pre}{strs[a_nm]}{rid}="{val}"')
        xml.append("  " * depth + f"<{strs[name]} " + " ".join(attrs) + ">"); depth += 1
    if typ == 0x0103: depth -= 1
    p += size
print("\n".join(xml))
results.append(ok(depth == 0, "manifest elements balanced"))

# ---------------- ARSC decode
a = z.read("resources.arsc")
typ, hs, size, npk = struct.unpack_from("<HHII", a, 0)
results.append(ok(typ == 2 and size == len(a) and npk == 1, "resources.arsc table header valid"))
gstr, p = decode_pool(a, 12)
typ, hs, size = struct.unpack_from("<HHI", a, p); pkg = p
pid, = struct.unpack_from("<I", a, p + 8); name = a[p + 12:p + 268].decode("utf-16-le").rstrip("\x00")
tso, _, kso, _ = struct.unpack_from("<IIII", a, p + 268)
tstr, _ = decode_pool(a, pkg + tso); kstr, _ = decode_pool(a, pkg + kso)
q = pkg + hs
found = None
while q < pkg + size:
    t2, h2, s2 = struct.unpack_from("<HHI", a, q)
    if q < pkg + kso + 1: pass
    if t2 == 0x0201:
        tid, _, _, ecount, estart = struct.unpack_from("<BBHII", a, q + 8)
        dens, = struct.unpack_from("<H", a, q + 20 + 14)
        eo, = struct.unpack_from("<I", a, q + h2)
        esz, efl, key = struct.unpack_from("<HHI", a, q + estart + eo)
        vsz, _, vt, vd = struct.unpack_from("<HBBI", a, q + estart + eo + esz)
        found = (f"0x{pid:02x}{tid:02x}0000", tstr[tid - 1], kstr[key], gstr[vd], dens)
    q += s2 if t2 in (0x0202, 0x0201) else s2
print("resource:", found, "package", name)
results.append(ok(found and found[0] == "0x7f010000" and found[3] in z.namelist(), "icon resource 0x7f010000 points at a file inside the APK"))

# ---------------- DEX
d = z.read("classes.dex")
hdr = struct.unpack_from("<8sI20sIIIIIIIIIIIIIIIIIIII", d, 0)
magic, csum, sha, fsize, hsize, endian, _, _, map_off, ns, so, nt, to, np_, po, nf, fo, nm, mo, nc, co, dsz, doff = hdr
results.append(ok(magic == b"dex\n035\x00" and fsize == len(d) and hsize == 0x70 and endian == 0x12345678, "dex header"))
results.append(ok(csum == zlib.adler32(d[12:]) & 0xFFFFFFFF, "dex adler32 checksum"))
results.append(ok(sha == hashlib.sha1(d[32:]).digest(), "dex SHA-1 signature"))
results.append(ok(dsz % 4 == 0 and doff + dsz == fsize, "dex data section size/alignment"))
def uleb(b, p):
    r = s = 0
    while True:
        x = b[p]; p += 1; r |= (x & 0x7F) << s; s += 7
        if not x & 0x80: return r, p
S = []
for i in range(ns):
    o, = struct.unpack_from("<I", d, so + 4 * i); ln, q = uleb(d, o); S.append(d[q:q + ln].decode())
T = [S[struct.unpack_from("<I", d, to + 4 * i)[0]] for i in range(nt)]
P = []
for i in range(np_):
    sh, rt, pof = struct.unpack_from("<III", d, po + 12 * i)
    params = []
    if pof:
        n, = struct.unpack_from("<I", d, pof); params = [T[struct.unpack_from("<H", d, pof + 4 + 2 * k)[0]] for k in range(n)]
    P.append((S[sh], T[rt], params, rt, [struct.unpack_from("<H", d, pof + 4 + 2 * k)[0] for k in range(len(params))]))
Mx = []
for i in range(nm):
    ci, pi, ni = struct.unpack_from("<HHI", d, mo + 8 * i); Mx.append((ci, ni, pi))
results.append(ok(S == sorted(S) and len(set(S)) == len(S), "dex strings sorted and unique"))
tsi = [struct.unpack_from("<I", d, to + 4 * i)[0] for i in range(nt)]
results.append(ok(tsi == sorted(tsi), "dex types sorted"))
results.append(ok([(x[3], x[4]) for x in P] == sorted((x[3], x[4]) for x in P), "dex protos sorted"))
results.append(ok(Mx == sorted(Mx), "dex methods sorted"))
for x in P:
    exp = "".join("L" if t[0] in "L[" else t for t in [x[1]] + x[2]); assert exp == x[0], x
results.append(ok(True, "dex proto shorties consistent"))
mcount, = struct.unpack_from("<I", d, map_off); last = -1; mitems = []
for i in range(mcount):
    ty, _, cnt, off = struct.unpack_from("<HHII", d, map_off + 4 + 12 * i); mitems.append((ty, cnt, off))
results.append(ok(all(mitems[i][2] < mitems[i + 1][2] for i in range(len(mitems) - 1)), "dex map list in offset order"))
mname = lambda i: f"{T[Mx[i][0]]}->{S[Mx[i][1]]}({''.join(P[Mx[i][2]][2])}){P[Mx[i][2]][1]}"
ci, acc, sup, _, src, _, cdo, _ = struct.unpack_from("<IIIIIIII", d, co)
print("class", T[ci], "extends", T[sup])
p = cdo; sf, p = uleb(d, p); inf, p = uleb(d, p); dm, p = uleb(d, p); vm, p = uleb(d, p)
OPS = {0x0e: "return-void", 0x12: "const/4", 0x13: "const/16", 0x14: "const", 0x0c: "move-result-object", 0x1a: "const-string",
       0x22: "new-instance", 0x6e: "invoke-virtual", 0x6f: "invoke-super", 0x70: "invoke-direct"}
for kind, cnt in (("direct", dm), ("virtual", vm)):
    idx = 0
    for _ in range(cnt):
        diff, p = uleb(d, p); fl, p = uleb(d, p); cof, p = uleb(d, p); idx += diff
        regs, ins, outs, tries, dbg, isz = struct.unpack_from("<HHHHII", d, cof)
        print(f"  {kind} {mname(idx)} flags=0x{fl:x} regs={regs} ins={ins} outs={outs}")
        u = list(struct.unpack_from("<%dH" % isz, d, cof + 16)); k = 0
        while k < len(u):
            op = u[k] & 0xFF; a = u[k] >> 8; name = OPS.get(op, f"??{op:02x}")
            if op in (0x6e, 0x6f, 0x70):
                n = a >> 4; regsl = [(u[k + 2] >> (4 * j)) & 0xF for j in range(4)] + [a & 0xF]
                assert max(regsl[:n]) < regs; print(f"    {name} {{{', '.join('v%d' % r for r in regsl[:n])}}}, {mname(u[k + 1])}"); k += 3
            elif op == 0x12: print(f"    {name} v{a & 0xF}, {((a >> 4) ^ 8) - 8}"); k += 1
            elif op == 0x13: print(f"    {name} v{a}, 0x{u[k + 1]:x}"); k += 2
            elif op == 0x14: print(f"    {name} v{a}, 0x{u[k + 1] | (u[k + 2] << 16):08x}"); k += 3
            elif op == 0x1a: print(f'    {name} v{a}, "{S[u[k + 1]]}"'); k += 2
            elif op == 0x22: print(f"    {name} v{a}, {T[u[k + 1]]}"); k += 2
            elif op == 0x0c: print(f"    {name} v{a}"); k += 1
            elif op == 0x0e: print(f"    {name}"); k += 1
            else: raise SystemExit("unknown opcode %x" % op)
results.append(ok(True, "dex bytecode decodes cleanly, all registers in range"))
print("\nALL CHECKS PASSED" if all(results) else "\nSOME CHECKS FAILED")

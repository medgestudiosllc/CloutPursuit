#!/usr/bin/env python3
"""
Clout Pursuit — Android APK builder (no Android SDK required).

Builds a WebView wrapper app around assets/index.html:
  * classes.dex        hand-assembled Dalvik bytecode for MainActivity
  * AndroidManifest.xml in Android binary XML (AXML)
  * resources.arsc     one drawable resource (the launcher icon)
  * APK zip with 4-byte alignment for stored entries
  * v1 (JAR) + v2 (APK Signature Scheme) signatures with a self-signed RSA key

Usage: python3 build_apk.py <index.html> <out.apk>
"""
import struct, hashlib, zlib, base64, os, sys, datetime

PKG = "com.cloutpursuit.game"
ACT = PKG + ".MainActivity"
ACT_DESC = "L" + ACT.replace(".", "/") + ";"
APP_LABEL = "Clout Pursuit"
VERSION_CODE, VERSION_NAME = 1, "0.1.0"
MIN_SDK, TARGET_SDK = 24, 34

# --------------------------------------------------------------- DEX
def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: out.append(b | 0x80)
        else:
            out.append(b); return bytes(out)

def shorty_of(t):
    return "L" if t[0] in "L[" else t

class DexBuilder:
    def __init__(self):
        self.strings, self.types, self.protos, self.methods = set(), set(), set(), set()
        self.classes = []
    def s(self, x): self.strings.add(x); return ("s", x)
    def t(self, x): self.types.add(x); self.strings.add(x); return ("t", x)
    def p(self, ret, params):
        params = tuple(params)
        self.t(ret); [self.t(x) for x in params]
        sh = shorty_of(ret) + "".join(shorty_of(x) for x in params); self.s(sh)
        key = (ret, params, sh); self.protos.add(key); return ("p", key)
    def m(self, cls, name, ret, params):
        self.t(cls); self.s(name); pk = self.p(ret, params)[1]
        key = (cls, name, pk); self.methods.add(key); return ("m", key)

    def build(self):
        S = sorted(self.strings)
        sidx = {x: i for i, x in enumerate(S)}
        T = sorted(self.types, key=lambda x: sidx[x])
        tidx = {x: i for i, x in enumerate(T)}
        P = sorted(self.protos, key=lambda k: (tidx[k[0]], [tidx[x] for x in k[1]]))
        pidx = {x: i for i, x in enumerate(P)}
        Mt = sorted(self.methods, key=lambda k: (tidx[k[0]], sidx[k[1]], pidx[k[2]]))
        midx = {x: i for i, x in enumerate(Mt)}
        resolve = lambda r: {"s": sidx, "t": tidx, "p": pidx, "m": midx}[r[0]][r[1]]
        self.idx = dict(s=sidx, t=tidx, p=pidx, m=midx)

        n_s, n_t, n_p, n_m, n_c = len(S), len(T), len(P), len(Mt), len(self.classes)
        off = 0x70
        string_ids_off = off; off += 4 * n_s
        type_ids_off = off; off += 4 * n_t
        proto_ids_off = off; off += 12 * n_p
        method_ids_off = off; off += 8 * n_m
        class_defs_off = off; off += 32 * n_c
        data_off = off
        data = bytearray()
        def here(): return data_off + len(data)
        def align4():
            while len(data) % 4: data.append(0)

        # type lists (proto parameters)
        tl_off, tl_count, tl_first = {}, 0, None
        for k in P:
            if not k[1] or k[1] in tl_off: continue
            align4(); tl_off[k[1]] = here()
            if tl_first is None: tl_first = here()
            data += struct.pack("<I", len(k[1]))
            for x in k[1]: data += struct.pack("<H", tidx[x])
            tl_count += 1
        # code items
        code_first, code_count = None, 0
        for c in self.classes:
            for meth in c["direct"] + c["virtual"]:
                align4(); meth["code_off"] = here()
                if code_first is None: code_first = here()
                insns = []
                for ins in meth["code"]:
                    insns += [resolve(u) if isinstance(u, tuple) else u for u in ins]
                data += struct.pack("<HHHHII", meth["regs"], meth["ins"], meth["outs"], 0, 0, len(insns))
                for u in insns: data += struct.pack("<H", u & 0xFFFF)
                code_count += 1
        # string data
        sd_first = here(); sd_off = []
        for x in S:
            sd_off.append(here())
            b = x.encode("utf-8")
            assert all(ch < 0x80 for ch in b), "ASCII only in this builder"
            data += uleb(len(x)) + b + b"\x00"
        # class data
        cd_first = here()
        for c in self.classes:
            c["class_data_off"] = here()
            data += uleb(0) + uleb(0) + uleb(len(c["direct"])) + uleb(len(c["virtual"]))
            for group in ("direct", "virtual"):
                ms = sorted(c[group], key=lambda mm: midx[mm["ref"][1]])
                prev = 0
                for mm in ms:
                    mi = midx[mm["ref"][1]]
                    data += uleb(mi - prev) + uleb(mm["flags"]) + uleb(mm["code_off"]); prev = mi
        align4()
        map_off = here()
        items = [(0x0000, 1, 0), (0x0001, n_s, string_ids_off), (0x0002, n_t, type_ids_off),
                 (0x0003, n_p, proto_ids_off), (0x0005, n_m, method_ids_off), (0x0006, n_c, class_defs_off)]
        if tl_count: items.append((0x1001, tl_count, tl_first))
        items += [(0x2001, code_count, code_first), (0x2002, n_s, sd_first), (0x2000, n_c, cd_first)]
        items.append((0x1000, 1, map_off))
        data += struct.pack("<I", len(items))
        for ty, cnt, o in items: data += struct.pack("<HHII", ty, 0, cnt, o)
        file_size = data_off + len(data)

        out = bytearray(0x70)
        for o in sd_off: out += struct.pack("<I", o)
        for x in T: out += struct.pack("<I", sidx[x])
        for k in P:
            out += struct.pack("<III", sidx[k[2]], tidx[k[0]], tl_off.get(k[1], 0) if k[1] else 0)
        for k in Mt: out += struct.pack("<HHI", tidx[k[0]], pidx[k[2]], sidx[k[1]])
        for c in self.classes:
            out += struct.pack("<IIIIIIII", tidx[c["name"]], c["flags"], tidx[c["super"]], 0,
                               0xFFFFFFFF, 0, c["class_data_off"], 0)
        assert len(out) == data_off
        out += data
        hdr = struct.pack("<8sI20sIIIIIIIIIIIIIIIIIIII", b"dex\n035\x00", 0, b"\x00" * 20, file_size, 0x70,
                          0x12345678, 0, 0, map_off, n_s, string_ids_off, n_t, type_ids_off, n_p,
                          proto_ids_off, 0, 0, n_m, method_ids_off, n_c, class_defs_off,
                          file_size - data_off, data_off)
        out[0:0x70] = hdr
        out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
        out[8:12] = struct.pack("<I", zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF)
        return bytes(out)

# instruction encoders (lists of 16-bit code units; tuples are resolved to indices)
def i35c(op, regs, ref):
    r = list(regs) + [0] * (5 - len(regs))
    return [op | (len(regs) << 12) | (r[4] << 8), ref, r[0] | (r[1] << 4) | (r[2] << 8) | (r[3] << 12)]
def i21c(op, a, ref): return [op | (a << 8), ref]
def i11x(op, a): return [op | (a << 8)]
def const4(a, lit): return [0x12 | (a << 8) | ((lit & 0xF) << 12)]
def const16(a, lit): return [0x13 | (a << 8), lit & 0xFFFF]
def const32(a, lit): return [0x14 | (a << 8), lit & 0xFFFF, (lit >> 16) & 0xFFFF]
RETURN_VOID = [0x000E]
INVOKE_VIRTUAL, INVOKE_SUPER, INVOKE_DIRECT = 0x6E, 0x6F, 0x70
NEW_INSTANCE, CONST_STRING, MOVE_RESULT_OBJECT = 0x22, 0x1A, 0x0C

def make_dex():
    d = DexBuilder()
    A, V, Z, I = "Landroid/app/Activity;", "V", "Z", "I"
    WV, WS = "Landroid/webkit/WebView;", "Landroid/webkit/WebSettings;"
    VIEW, WIN = "Landroid/view/View;", "Landroid/view/Window;"
    act_init = d.m(A, "<init>", V, [])
    act_onCreate = d.m(A, "onCreate", V, ["Landroid/os/Bundle;"])
    act_setContent = d.m(A, "setContentView", V, [VIEW])
    act_reqFeature = d.m(A, "requestWindowFeature", Z, [I])
    act_getWindow = d.m(A, "getWindow", WIN, [])
    win_setFlags = d.m(WIN, "setFlags", V, [I, I])
    wv_init = d.m(WV, "<init>", V, ["Landroid/content/Context;"])
    wv_settings = d.m(WV, "getSettings", WS, [])
    wv_load = d.m(WV, "loadUrl", V, ["Ljava/lang/String;"])
    ws_js = d.m(WS, "setJavaScriptEnabled", V, [Z])
    ws_dom = d.m(WS, "setDomStorageEnabled", V, [Z])
    ws_media = d.m(WS, "setMediaPlaybackRequiresUserGesture", V, [Z])
    v_keep = d.m(VIEW, "setKeepScreenOn", V, [Z])
    v_bg = d.m(VIEW, "setBackgroundColor", V, [I])
    v_ui = d.m(VIEW, "setSystemUiVisibility", V, [I])
    my_init = d.m(ACT_DESC, "<init>", V, [])
    my_onCreate = d.m(ACT_DESC, "onCreate", V, ["Landroid/os/Bundle;"])
    t_wv = d.t(WV); url = d.s("file:///android_asset/index.html")
    d.t(ACT_DESC); d.t(A)
    # registers: v0 webview, v1 tmp, v2 tmp, v3 = this, v4 = bundle
    on_create = [
        i35c(INVOKE_SUPER, [3, 4], act_onCreate),
        const4(1, 1), i35c(INVOKE_VIRTUAL, [3, 1], act_reqFeature),          # FEATURE_NO_TITLE
        i35c(INVOKE_VIRTUAL, [3], act_getWindow), i11x(MOVE_RESULT_OBJECT, 1),
        const16(2, 0x400), i35c(INVOKE_VIRTUAL, [1, 2, 2], win_setFlags),   # FLAG_FULLSCREEN
        i21c(NEW_INSTANCE, 0, t_wv), i35c(INVOKE_DIRECT, [0, 3], wv_init),
        i35c(INVOKE_VIRTUAL, [0], wv_settings), i11x(MOVE_RESULT_OBJECT, 1),
        const4(2, 1), i35c(INVOKE_VIRTUAL, [1, 2], ws_js), i35c(INVOKE_VIRTUAL, [1, 2], ws_dom),
        const4(2, 0), i35c(INVOKE_VIRTUAL, [1, 2], ws_media),
        const4(1, 1), i35c(INVOKE_VIRTUAL, [0, 1], v_keep),
        const32(1, 0xFF0D0C10), i35c(INVOKE_VIRTUAL, [0, 1], v_bg),
        i35c(INVOKE_VIRTUAL, [3, 0], act_setContent),
        const16(1, 0x1706), i35c(INVOKE_VIRTUAL, [0, 1], v_ui),               # immersive sticky
        i21c(CONST_STRING, 1, url), i35c(INVOKE_VIRTUAL, [0, 1], wv_load),
        RETURN_VOID]
    ctor = [i35c(INVOKE_DIRECT, [0], act_init), RETURN_VOID]
    d.classes.append(dict(name=ACT_DESC, super=A, flags=0x0001,
        direct=[dict(ref=my_init, flags=0x10001, regs=1, ins=1, outs=1, code=ctor)],
        virtual=[dict(ref=my_onCreate, flags=0x0004, regs=5, ins=2, outs=3, code=on_create)]))
    return d.build()

# --------------------------------------------------------------- chunks / string pools
def chunk(typ, header_rest, body, header_size=None):
    hs = header_size or 8 + len(header_rest)
    payload = header_rest + body
    while (8 + len(payload)) % 4: payload += b"\x00"
    return struct.pack("<HHI", typ, hs, 8 + len(payload)) + payload

def string_pool(strings, utf8=False):
    offs, blob = [], bytearray()
    for s in strings:
        offs.append(len(blob))
        if utf8:
            b = s.encode("utf-8"); assert len(s) < 128 and len(b) < 128
            blob += bytes([len(s), len(b)]) + b + b"\x00"
        else:
            u = s.encode("utf-16-le"); assert len(s) < 0x8000
            blob += struct.pack("<H", len(s)) + u + b"\x00\x00"
    while len(blob) % 4: blob.append(0)
    strings_start = 28 + 4 * len(strings)
    hdr = struct.pack("<IIIII", len(strings), 0, 0x100 if utf8 else 0, strings_start, 0)
    body = b"".join(struct.pack("<I", o) for o in offs) + bytes(blob)
    return chunk(0x0001, hdr, body, 28)

# --------------------------------------------------------------- AXML manifest
ATTR = {  # android:attr name -> resource id
    "versionCode": 0x0101021B, "versionName": 0x0101021C, "minSdkVersion": 0x0101020C,
    "targetSdkVersion": 0x01010270, "name": 0x01010003, "label": 0x01010001, "icon": 0x01010002,
    "hardwareAccelerated": 0x010102D3, "exported": 0x01010010, "screenOrientation": 0x0101001E,
    "configChanges": 0x0101001F,
}
T_REF, T_STR, T_DEC, T_HEX, T_BOOL = 0x01, 0x03, 0x10, 0x11, 0x12
ANDROID_NS = "http://schemas.android.com/apk/res/android"

def make_manifest(icon_res_id):
    tree = ("manifest", [("versionCode", T_DEC, VERSION_CODE), ("versionName", T_STR, VERSION_NAME), (None, "package", PKG)], [
        ("uses-sdk", [("minSdkVersion", T_DEC, MIN_SDK), ("targetSdkVersion", T_DEC, TARGET_SDK)], []),
        ("uses-permission", [("name", T_STR, "android.permission.INTERNET")], []),
        ("application", [("label", T_STR, APP_LABEL), ("icon", T_REF, icon_res_id), ("hardwareAccelerated", T_BOOL, True)], [
            ("activity", [("name", T_STR, ACT), ("exported", T_BOOL, True), ("screenOrientation", T_DEC, 6),
                          ("configChanges", T_HEX, 0x0FF0)], [
                ("intent-filter", [], [
                    ("action", [("name", T_STR, "android.intent.action.MAIN")], []),
                    ("category", [("name", T_STR, "android.intent.category.LAUNCHER")], [])])])])])
    attr_names = list(ATTR.keys())
    strings = list(attr_names)
    def S(x):
        if x not in strings: strings.append(x)
        return strings.index(x)
    S("android"); S(ANDROID_NS)
    def collect(n):
        S(n[0])
        for a in n[1]:
            if a[0] is None: S(a[1]); S(a[2])
            elif a[1] == T_STR: S(a[2])
        for c in n[2]: collect(c)
    collect(tree)
    NONE = 0xFFFFFFFF
    nodes = bytearray(); line = [1]
    def emit(n):
        attrs = []
        for a in n[1]:
            if a[0] is None:
                attrs.append((ATTR_SORT_PLAIN, NONE, S(a[1]), S(a[2]), T_STR, S(a[2])))
            else:
                nm, ty, val = a
                raw = S(val) if ty == T_STR else NONE
                data = S(val) if ty == T_STR else (0xFFFFFFFF if val is True else 0 if val is False else val)
                attrs.append((ATTR[nm], S(ANDROID_NS), attr_names.index(nm), raw, ty, data))
        attrs.sort(key=lambda x: x[0])
        ext = struct.pack("<IIHHHHHH", NONE, S(n[0]), 20, 20, len(attrs), 0, 0, 0)
        body = ext + b"".join(struct.pack("<IIIHBBI", ns, nm, raw, 8, 0, ty, dt) for _, ns, nm, raw, ty, dt in attrs)
        nodes.extend(chunk(0x0102, struct.pack("<II", line[0], NONE), body, 16)); line[0] += 1
        for c in n[2]: emit(c)
        nodes.extend(chunk(0x0103, struct.pack("<II", line[0], NONE), struct.pack("<II", NONE, S(n[0])), 16)); line[0] += 1
    ns_body = struct.pack("<II", S("android"), S(ANDROID_NS))
    start_ns = chunk(0x0100, struct.pack("<II", 1, NONE), ns_body, 16)
    emit(tree)
    end_ns = chunk(0x0101, struct.pack("<II", line[0], NONE), ns_body, 16)
    pool = string_pool(strings)
    resmap = chunk(0x0180, b"", b"".join(struct.pack("<I", ATTR[a]) for a in attr_names), 8)
    body = pool + resmap + start_ns + bytes(nodes) + end_ns
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body
ATTR_SORT_PLAIN = 0x7FFFFFFF  # plain attributes (no res id) sort last

# --------------------------------------------------------------- resources.arsc
def make_arsc(icon_path):
    gpool = string_pool([icon_path], utf8=True)
    type_pool = string_pool(["drawable"], utf8=True)
    key_pool = string_pool(["icon"], utf8=True)
    spec = chunk(0x0202, struct.pack("<BBHI", 1, 0, 0, 1), struct.pack("<I", 0x0100), 16)  # entry varies by density
    config = bytearray(64); struct.pack_into("<I", config, 0, 64); struct.pack_into("<H", config, 14, 640)  # xxxhdpi
    entries = struct.pack("<HHI", 8, 0, 0) + struct.pack("<HBBI", 8, 0, T_STR, 0)
    type_hdr_size = 20 + 64
    offsets = struct.pack("<I", 0)
    entries_start = type_hdr_size + len(offsets)
    tchunk = chunk(0x0201, struct.pack("<BBHII", 1, 0, 0, 1, entries_start) + bytes(config), offsets + entries, type_hdr_size)
    name = PKG.encode("utf-16-le"); name = name + b"\x00" * (256 - len(name))
    pkg_hdr_size = 288
    type_strings_off = pkg_hdr_size
    key_strings_off = pkg_hdr_size + len(type_pool)
    pkg_hdr_rest = struct.pack("<I", 0x7F) + name + struct.pack("<IIIII", type_strings_off, 1, key_strings_off, 1, 0)
    pkg = chunk(0x0200, pkg_hdr_rest, type_pool + key_pool + spec + tchunk, pkg_hdr_size)
    body = gpool + pkg
    return struct.pack("<HHII", 0x0002, 12, 12 + len(body), 1) + body

# --------------------------------------------------------------- icon
def make_icon(path):
    from PIL import Image, ImageDraw, ImageFont
    S = 192
    img = Image.new("RGBA", (S, S), (13, 12, 16, 255))
    dr = ImageDraw.Draw(img)
    for i in range(6):  # stage light beams
        dr.polygon([(30 + i * 28, 0), (14 + i * 28, S), (46 + i * 28, S)], fill=(40, 22, 30, 255))
    font = None
    for f in ["/usr/share/fonts/opentype/inter/Inter-Black.otf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]:
        if os.path.exists(f): font = ImageFont.truetype(f, 92); break
    def center(t, y, fill, dx=0):
        w = dr.textlength(t, font=font); dr.text(((S - w) / 2 + dx, y), t, font=font, fill=fill)
    center("CP", 38 + 5, (255, 59, 59, 255), 5)
    center("CP", 38, (245, 183, 10, 255))
    dr.rectangle([46, 150, 146, 156], fill=(255, 59, 59, 255))
    img.save(path, optimize=True)
    return open(path, "rb").read()

# --------------------------------------------------------------- zip writer (aligned)
def build_zip(entries):
    """entries: list of (name, data, store:boolean). Stored entries get 4-byte aligned data."""
    out = bytearray(); central = bytearray()
    dos_time, dos_date = 0, (2026 - 1980) << 9 | 11 << 5 | 2
    for name, data, store in entries:
        nb = name.encode()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        if store: comp, method = data, 0
        else:
            co = zlib.compressobj(9, zlib.DEFLATED, -15); comp = co.compress(data) + co.flush(); method = 8
        off = len(out)
        extra = b""
        if store:
            pad = (4 - (off + 30 + len(nb)) % 4) % 4
            extra = b"\x00" * pad
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x0800, method, dos_time, dos_date, crc,
                           len(comp), len(data), len(nb), len(extra)) + nb + extra + comp
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0x0800, method, dos_time, dos_date,
                               crc, len(comp), len(data), len(nb), 0, 0, 0, 0, 0, off) + nb
    cd_off = len(out)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), cd_off, 0)
    return bytes(out), bytes(central), eocd

# --------------------------------------------------------------- signing
def load_or_make_key(keydir):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    kp, cp = os.path.join(keydir, "cloutpursuit-test-key.pem"), os.path.join(keydir, "cloutpursuit-test-cert.pem")
    if os.path.exists(kp) and os.path.exists(cp):
        key = serialization.load_pem_private_key(open(kp, "rb").read(), None)
        cert = x509.load_pem_x509_certificate(open(cp, "rb").read())
        return key, cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Clout Pursuit Test"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Clout Pursuit Prototype")])
    now = datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365 * 30)).sign(key, hashes.SHA256()))
    os.makedirs(keydir, exist_ok=True)
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert

def v1_files(entries, key, cert):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7
    b64 = lambda d: base64.b64encode(d).decode()
    mf = "Manifest-Version: 1.0\r\nCreated-By: 1.0 (Clout Pursuit builder)\r\n\r\n"
    sections = []
    for name, data, _ in entries:
        sec = f"Name: {name}\r\nSHA-256-Digest: {b64(hashlib.sha256(data).digest())}\r\n\r\n"
        assert all(len(l) <= 70 for l in sec.split("\r\n")), "manifest line too long"
        sections.append((name, sec)); mf += sec
    mfb = mf.encode()
    sf = ("Signature-Version: 1.0\r\nCreated-By: 1.0 (Clout Pursuit builder)\r\n"
          f"SHA-256-Digest-Manifest: {b64(hashlib.sha256(mfb).digest())}\r\nX-Android-APK-Signed: 2\r\n\r\n")
    for name, sec in sections:
        sf += f"Name: {name}\r\nSHA-256-Digest: {b64(hashlib.sha256(sec.encode()).digest())}\r\n\r\n"
    sfb = sf.encode()
    rsa = (pkcs7.PKCS7SignatureBuilder().set_data(sfb).add_signer(cert, key, hashes.SHA256())
           .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.NoAttributes]))
    return [("META-INF/MANIFEST.MF", mfb, False), ("META-INF/CERT.SF", sfb, False), ("META-INF/CERT.RSA", rsa, False)]

def lp(b): return struct.pack("<I", len(b)) + b

def v2_sign(zip_entries_blob, central, eocd, key, cert):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    def content_digest(sections):
        chunks = []
        for sec in sections:
            for i in range(0, len(sec), 1 << 20):
                c = sec[i:i + (1 << 20)]
                chunks.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(c)) + c).digest())
        return hashlib.sha256(b"\x5a" + struct.pack("<I", len(chunks)) + b"".join(chunks)).digest()
    cd_off = len(zip_entries_blob)
    eocd_for_digest = eocd[:16] + struct.pack("<I", cd_off) + eocd[20:]
    digest = content_digest([zip_entries_blob, central, eocd_for_digest])
    ALG = 0x0103  # RSASSA-PKCS1-v1_5 with SHA2-256
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    signed_data = lp(lp(struct.pack("<I", ALG) + lp(digest))) + lp(lp(cert_der)) + lp(b"")
    sig = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = lp(signed_data) + lp(lp(struct.pack("<I", ALG) + lp(sig))) + lp(pub)
    v2_value = lp(lp(signer))
    pair = struct.pack("<QI", 4 + len(v2_value), 0x7109871A) + v2_value
    block_size = len(pair) + 8 + 16
    block = struct.pack("<Q", block_size) + pair + struct.pack("<Q", block_size) + b"APK Sig Block 42"
    new_eocd = eocd[:16] + struct.pack("<I", cd_off + len(block)) + eocd[20:]
    return zip_entries_blob + block + central + new_eocd

# --------------------------------------------------------------- main
def main(html_path, out_path):
    here = os.path.dirname(os.path.abspath(__file__))
    build = os.path.join(here, "build"); os.makedirs(build, exist_ok=True)
    icon_rel = "res/drawable/icon.png"
    icon = make_icon(os.path.join(build, "icon.png"))
    dex = make_dex(); open(os.path.join(build, "classes.dex"), "wb").write(dex)
    manifest = make_manifest(0x7F010000); open(os.path.join(build, "AndroidManifest.xml"), "wb").write(manifest)
    arsc = make_arsc(icon_rel); open(os.path.join(build, "resources.arsc"), "wb").write(arsc)
    html = open(html_path, "rb").read()
    entries = [("AndroidManifest.xml", manifest, False), ("classes.dex", dex, False),
               ("resources.arsc", arsc, True), (icon_rel, icon, True), ("assets/index.html", html, False)]
    key, cert = load_or_make_key(os.path.join(here, "keys"))
    entries += v1_files(entries, key, cert)
    blob, central, eocd = build_zip(entries)
    apk = v2_sign(blob, central, eocd, key, cert)
    open(out_path, "wb").write(apk)
    print(f"wrote {out_path}: {len(apk)} bytes; dex {len(dex)}, manifest {len(manifest)}, arsc {len(arsc)}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

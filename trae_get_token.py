#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trae Token 提取器 · trae_get_token.py
────────────────────────────────────────────────────────────
一键从 Trae 官方客户端本地数据里解出 refreshToken / accessToken，
免抓包、免装依赖（纯 Python 标准库，自己实现 AES-128-CBC）。

✨ 特性
  • 零依赖     纯标准库，无需 pip install
  • 免抓包     直接读客户端 storage.json 并自动解密
  • 一键输出   直接给出可粘贴的 TRAE_ACCOUNTS（含 accessToken，省一次续期）
  • 自动找路径 自动探测 Trae CN / TRAE SOLO 等常见目录

🚀 使用方法
  1. 打开 Trae 客户端并登录一次（确保已产生凭据）
  2. 运行：python trae_get_token.py
  3. 复制输出的 TRAE_ACCOUNTS 整串，填进青龙面板 / Actions secret

⚠️ 为什么优先用 TRAE_ACCOUNTS 而不是单给 refreshToken
  refreshToken 续期绑定客户端标识，只拿这一串去 ExchangeToken 会被服务端
  拒成 10101「refresh token is not matched to the client」。带上 accessToken
  就能直接复用（约 14 天有效），过期后才需要续期，而那时本脚本会给出新的一对。

📌 说明
  • 只读取本机自己的客户端凭据，不联网、不上传，安全无风险。
  • 多账号：在客户端依次登录每个账号并各运行一次本脚本即可。
────────────────────────────────────────────────────────────
"""
import base64, datetime, hashlib, json, os, sys, re

# ── 让 Windows 控制台也能正常打印 emoji ──
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SALT_A = bytes([82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37])
SALT_B = bytes([31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125])
SALT_AES = bytes(a ^ b for a, b in zip(SALT_A, SALT_B))
STORAGE_KEY = "iCubeAuthInfo://icube.cloudide"

# ══════════ 纯标准库 AES-128-CBC 解密 ══════════
def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

def _build_sbox():
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if _gmul(i, j) == 1:
                inv[i] = j; break
    sb = [0] * 256
    for i in range(256):
        x = inv[i] if i else 0; s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF; s ^= x
        sb[i] = s ^ 0x63
    return sb

SBOX = _build_sbox()
INV = [0] * 256
for _i, _v in enumerate(SBOX): INV[_v] = _i
RC = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def _expand(key):
    w = [list(key[i*4:i*4+4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i-1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RC[i//4-1]
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return w

def _rk(w, r):
    ws = w[r*4:r*4+4]
    return [ws[c][k] for c in range(4) for k in range(4)]

def _addrk(s, k): return [s[i] ^ k[i] for i in range(16)]
def _isub(s): return [INV[b] for b in s]
def _ishift(s): return [s[0],s[13],s[10],s[7], s[4],s[1],s[14],s[11], s[8],s[5],s[2],s[15], s[12],s[9],s[6],s[3]]

def _imix(s):
    o = []
    for c in range(4):
        a = s[c*4:c*4+4]
        o += [_gmul(a[0],14)^_gmul(a[1],11)^_gmul(a[2],13)^_gmul(a[3],9),
              _gmul(a[0],9)^_gmul(a[1],14)^_gmul(a[2],11)^_gmul(a[3],13),
              _gmul(a[0],13)^_gmul(a[1],9)^_gmul(a[2],14)^_gmul(a[3],11),
              _gmul(a[0],11)^_gmul(a[1],13)^_gmul(a[2],9)^_gmul(a[3],14)]
    return o

def aes128_cbc_decrypt(key, iv, data):
    w = _expand(key); out = b""; prev = list(iv)
    for off in range(0, len(data), 16):
        blk = list(data[off:off+16]); s = _addrk(blk, _rk(w, 10))
        for r in range(9, 0, -1):
            s = _ishift(s); s = _isub(s); s = _addrk(s, _rk(w, r)); s = _imix(s)
        s = _ishift(s); s = _isub(s); s = _addrk(s, _rk(w, 0))
        out += bytes(a ^ b for a, b in zip(s, prev)); prev = blk
    return out

# ══════════ 解密 storage.json 里的凭据 ══════════
def decrypt_storage_value(b64):
    buf = base64.b64decode(b64)
    rb, enc = buf[6:38], buf[38:]
    h = hashlib.sha512(rb).digest()
    fh = hashlib.sha512(h + SALT_AES).digest()
    pt = aes128_cbc_decrypt(fh[:16], fh[16:32], enc)[64:]
    return pt.rstrip(b"\x00").rstrip()

def candidate_paths():
    home = os.path.expanduser("~")
    names = ("Trae CN", "TRAE SOLO CN", "TRAE SOLO", "Trae")
    sub = ("User", "globalStorage", "storage.json")
    ad = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    for n in names:
        p = os.path.join(ad, n, *sub)
        if os.path.isfile(p): yield p
    lib = os.path.join(home, "Library", "Application Support")
    for n in names:
        p = os.path.join(lib, n, *sub)
        if os.path.isfile(p): yield p
    for base in (home, os.path.join(home, ".config")):
        for n in (".trae-cn", ".trae", "Trae CN", "TRAE SOLO CN"):
            p = os.path.join(base, n, *sub)
            if os.path.isfile(p): yield p

def extract(path):
    s = json.load(open(path, encoding="utf-8"))
    enc = s.get(STORAGE_KEY)
    if not enc: return None
    txt = decrypt_storage_value(enc).decode("utf-8", "replace")
    # 解密结果尾部常带填充残留，raw_decode 只取第一个完整 JSON 对象
    try:
        d, _ = json.JSONDecoder().raw_decode(txt)
    except ValueError:
        d = {}
    if not isinstance(d, dict):
        d = {}
    acct = d.get("account") or {}

    def pick(key):
        return d.get(key) or acct.get(key) or ""

    # 老格式（无 JSON 结构）回退到正则
    rt = pick("refreshToken") or (re.search(r'"refreshToken"\s*:\s*"([^"]+)"', txt) or [None, None])[1]
    at = pick("token") or (re.search(r'"token"\s*:\s*"([^"]+)"', txt) or [None, None])[1]
    uid = str(pick("userId") or (re.search(r'"userId"\s*:\s*"(\d+)"', txt) or [None, ""])[1] or "")
    nick = pick("username")
    return {"refreshToken": rt,
            "accessToken": at,
            "uid": uid,
            "nickname": nick,
            "deviceId": real_device_id(s),
            "expiredAt": d.get("expiredAt") or "",
            "refreshExpiredAt": d.get("refreshExpiredAt") or ""}


def real_device_id(storage):
    """取客户端真实设备号：storage.json 里 iCubeAuthInfo://icube-dc:<数字> 键。

    ⚠️ 这是签到的硬门槛。服务端按设备维度判重（claim 返回 9095
    「当前设备今日已经签到」），合成出来的 16 位数字会被判成不合格设备，
    一律回 9074「参与用户太多」—— 看起来像限流，实际是设备号无效。
    所以每个账号都必须配它自己客户端里那个真机号，不能共用、不能生成。"""
    for k in storage:
        if k.startswith("iCubeAuthInfo://icube-dc:"):
            d = k.split(":")[-1]
            if d.isdigit():
                return d
    return ""


def at_valid(expired_at):
    """accessToken 是否还没过期（expiredAt 是 UTC ISO8601）。"""
    try:
        t = datetime.datetime.strptime(expired_at.replace("Z", ""), "%Y-%m-%dT%H:%M:%S.%f")
    except Exception:
        try:
            t = datetime.datetime.strptime(expired_at.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return False
    return t - datetime.timedelta(minutes=1) > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def main():
    found = False
    accts = []
    for p in candidate_paths():
        try:
            r = extract(p)
        except Exception as e:
            print("[!] 解析失败 %s: %s" % (p, e)); continue
        if not r or not (r.get("refreshToken") or r.get("accessToken")): continue
        found = True
        print("=" * 64)
        print("[来源] %s" % p)
        if r.get("uid"):
            print("[账号] %s (UID %s)" % (r.get("nickname") or "-", r["uid"]))
        if r.get("deviceId"):
            print("[设备号] %s（真机号，签到必须带它）" % r["deviceId"])
        else:
            print("[设备号] ⚠️ 没找到 iCubeAuthInfo://icube-dc:* 键，该账号无法签到")
        if r.get("expiredAt"):
            live = at_valid(r["expiredAt"])
            print("[accessToken] %s，到期 %s" % ("✅ 未过期" if live else "⌛ 已过期", r["expiredAt"]))
        print("-" * 64)
        # 推荐写法：整串 TRAE_ACCOUNTS 直接粘进青龙/Actions，accessToken 一起给，
        # 省掉一次续期。只有 refreshToken 时续期会因"未绑定客户端"被拒（10101）。
        # deviceId 是真机号：服务端按设备维度判重，缺它或换成合成号一律 9074。
        one = {k: v for k, v in (("name", r.get("nickname")), ("uid", r.get("uid")),
                                 ("accessToken", r.get("accessToken")),
                                 ("refreshToken", r.get("refreshToken")),
                                 ("deviceId", r.get("deviceId"))) if v}
        accts.append(one)
        print("TRAE_ACCOUNTS（推荐，含 accessToken 与真机 deviceId）:")
        print(json.dumps([one], ensure_ascii=False))
        print("-" * 64)
        print("TRAE_REFRESH_TOKEN（旧写法，仅 refreshToken）:")
        print("TRAE_REFRESH_TOKEN = %s" % r.get("refreshToken"))
        print("=" * 64)
    if not found:
        print("[X] 没找到可用的 refreshToken。")
        print("    请先打开 Trae 客户端并登录一次，再运行本脚本。")
        return
    if len(accts) > 1:
        print("\n多账号合并写法（一次粘进 TRAE_ACCOUNTS）:")
        print(json.dumps(accts, ensure_ascii=False, indent=2))
        # 多账号最容易踩的坑：设备号必须两两不同，否则后签的会撞 9095/9074
        ids = [a.get("deviceId") for a in accts if a.get("deviceId")]
        if len(ids) != len(set(ids)):
            print("\n⚠️ 有账号共用同一个设备号！服务端按设备维度判重，"
                  "同一设备一天只能签一个账号，重复的账号签不上。")
        missing = [a.get("name") or a.get("uid") for a in accts if not a.get("deviceId")]
        if missing:
            print("\n⚠️ 这些账号缺 deviceId，签到会一直 9074：%s" % "、".join(missing))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trae 设备身份提取器 · trae_extract_device.py
────────────────────────────────────────────────────────────
用在「登录过 Trae 客户端的任意一台真机」上（不要求登录账号），
把该机器在 Trae 服务端登记过的『设备身份』一次性提全：

  • DeviceID          —— aha 服务端派发的设备号（iCubeAuthInfo://icube-dc:<号>）
  • privateKeyPEM     —— 该设备的 ECDSA P-256 私钥（本地生成、本地存）
  • publicKeyPEM      —— 对应的公钥（签到/续期要发给服务端验证）
  • MachineID         —— 机器特征（telemetry.machineId）

为什么必须提取完整身份，而不只是 16 位号？
  服务端按『设备身份』校验：每个能签到的账号都必须绑定一台真实设备的
  (DeviceID + 公钥)，续期/登录请求还要带上用私钥算出的设备签名
  （DeviceProof）。光抄一个 deviceId 数字没有用 —— 没有私钥就签不出
  DeviceProof，服务端不认，签到会一路 9074/10101。

用法（在被提取的机器上运行）：
  python trae_extract_device.py
  输出一行可直接粘走的 JSON。Windows / macOS 通用，纯标准库零依赖。

注意：只读本机 Trae 客户端数据，不联网、不上传。提取结果含私钥，
请当作机密文件保管，勿发到公开仓库 / 聊天记录截图。
"""
import base64, hashlib, json, os, sys

RESULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "trae_device_result.json")

# ── 让 Windows 控制台也能正常打印 ──
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SALT_A = bytes([82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37])
SALT_B = bytes([31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125])
SALT_AES = bytes(a ^ b for a, b in zip(SALT_A, SALT_B))

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

def decrypt_storage_value(b64):
    buf = base64.b64decode(b64)
    rb, enc = buf[6:38], buf[38:]
    h = hashlib.sha512(rb).digest()
    fh = hashlib.sha512(h + SALT_AES).digest()
    pt = aes128_cbc_decrypt(fh[:16], fh[16:32], enc)[64:]
    return pt.rstrip(b"\x00").rstrip()

def candidate_storage_paths():
    home = os.path.expanduser("~")
    ad = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    lib = os.path.join(home, "Library", "Application Support")
    names = ("Trae CN", "TRAE SOLO CN", "TRAE SOLO", "Trae")
    for base in (ad, lib):
        for n in names:
            p = os.path.join(base, n, "User", "globalStorage", "storage.json")
            if os.path.isfile(p):
                yield p

def extract(path):
    """返回 dict：deviceId / privateKeyPEM / publicKeyPEM / machineId / uid / name / storagePath"""
    with open(path, "r", encoding="utf-8") as fh:
        s = json.load(fh)
    out = {"storagePath": path}
    out["machineId"] = s.get("telemetry.machineId") or ""
    # deviceId + 其 ECDSA 密钥对
    for k, v in s.items():
        if k.startswith("iCubeAuthInfo://icube-dc:"):
            did = k.split(":")[-1]
            try:
                dec = decrypt_storage_value(v)
                d, _ = json.JSONDecoder().raw_decode(dec.decode("utf-8", "replace"))
            except Exception:
                d = {}
            if isinstance(d, dict) and d:
                out.update({"deviceId": did,
                            "privateKeyPEM": d.get("privateKeyPEM") or "",
                            "publicKeyPEM": d.get("publicKeyPEM") or ""})
                break
    # 登录账号（若有）
    enc = s.get("iCubeAuthInfo://icube.cloudide")
    if enc:
        try:
            txt = decrypt_storage_value(enc).decode("utf-8", "replace")
            d, _ = json.JSONDecoder().raw_decode(txt)
            out["uid"] = str((d or {}).get("userId") or "")
            out["name"] = ((d or {}).get("account") or {}).get("username") or ""
        except Exception:
            out["uid"] = out["name"] = ""
    return out

def main():
    # 默认只打印一行 JSON（窗口不滚动、不丢结果）；
    # --verbose 才打印来源/账号/DeviceID 等详情。
    verbose = "--verbose" in sys.argv
    found = False
    last = None
    for p in candidate_storage_paths():
        try:
            r = extract(p)
        except Exception as e:
            if verbose:
                print("[!] 解析失败 %s: %s" % (p, e))
            continue
        if not r.get("deviceId"):
            if verbose:
                print("[%s] 该机器还没有在 Trae 服务端登记过设备（无 icube-dc:* 键）。"
                      % p + " 先启动一次 Trae 客户端再重跑。")
            continue
        found = True
        last = r
        if verbose:
            print("=" * 64)
            print("[来源] %s" % p)
            print("[账号] %s (UID %s)" % (r.get("name") or "-", r.get("uid") or "-"))
            print("[DeviceID] %s" % r.get("deviceId"))
            print("[MachineID] %s" % r.get("machineId"))
            print("-" * 64)
            print(json.dumps(r, ensure_ascii=False))
            print("=" * 64)
    if found and last:
        print(json.dumps(last, ensure_ascii=False))
        # 双保险：同时写一份到同目录文件，超长 JSON 也能完整拿到
        try:
            with open(RESULT_FILE, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(last, ensure_ascii=False) + "\n")
            print("\n[已另存] %s" % RESULT_FILE)
        except Exception as e:
            print("\n[!] 结果写入文件失败: %s" % e)
    elif not found:
        print("[X] 没找到任何带设备登记的 storage.json。")
        print("    请先在这台机器上启动一次 Trae 客户端（不用登录）再运行本脚本。")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
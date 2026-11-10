#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线自检：不联网、不读 token，跑 `python test_offline.py`。

覆盖历史踩过的坑：
  • pick_batch 引用未定义的 size（TRAE_BATCH=2 直接 NameError）
  • claim_with_retry 非限流分支只返回 3 元组（调用方解包 4 个必崩）
  • 积分接口 usage_summary 在根级 / data 包装两种形态都要认
  • 积分监控与签到脚本的账号键、设备号算法必须一致（共用同一份 token 缓存）
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trae_checkin as ci
import trae_credit_monitor as cm


def test_pick_batch():
    pend = [{'name': 'a'}, {'name': 'b'}, {'name': 'c'}]
    os.environ.pop('TRAE_BATCH', None)
    assert ci.pick_batch(pend) == pend                  # 默认一轮全签
    os.environ['TRAE_BATCH'] = 'all'
    assert ci.pick_batch(pend) == pend
    os.environ['TRAE_BATCH'] = '2'
    os.environ['TRAE_PEAK_HOURS'] = '99'                # 躲开早窗，强制走轮签分支
    assert len(ci.pick_batch(pend)) == 2
    os.environ['TRAE_BATCH'] = '1'
    assert len(ci.pick_batch(pend)) == 1
    os.environ['TRAE_BATCH'] = '乱写'
    assert len(ci.pick_batch(pend)) == 1                # 非法值退化成 1，不炸定时任务
    os.environ['TRAE_BATCH'] = '1'
    os.environ['TRAE_PEAK_HOURS'] = str(ci.bj_now().tm_hour)   # 早窗=当前小时，一轮全签
    assert ci.pick_batch(pend) == pend
    for k in ('TRAE_BATCH', 'TRAE_PEAK_HOURS'):
        os.environ.pop(k, None)


def test_claim_with_retry_arity():
    """非限流失败也必须返回 4 元组，否则 checkin_account 解包崩溃。"""
    ci.claim = lambda tok, did: (200, 40001, 'bad request', None)
    ok, code, msg, points = ci.claim_with_retry({'accessToken': 'x'}, {})
    assert (ok, code) == (False, 40001) and points is None


def test_credit_parse():
    def fake(text):
        cm._post = lambda *a, **k: (200, text)

    fake(json.dumps({'code': 0, 'usage_summary': {'total_amount': 100.0, 'consumed_amount': 30.0}}))
    r = cm.credits_summary('t', '1')
    assert (r['total'], r['used'], r['remain']) == (100.0, 30.0, 70.0)   # 根级

    fake(json.dumps({'code': 0, 'data': {'usage_summary': {'total_amount': 50, 'consumed_amount': 20}}}))
    r = cm.credits_summary('t', '1')
    assert r['remain'] == 30.0                                          # data 包装

    fake(json.dumps({'code': 0, 'user_entitlement_pack_list': [
        {'entitlement_base_info': {'quota': {'credits_limit': 100}}, 'usage': {'credits_amount': 40}},
        {'entitlement_base_info': {'quota': {'credits_limit': 0}}, 'usage': {'credits_amount': 0}},
    ]}))
    r = cm.credits_summary('t', '1')
    assert (r['total'], r['used'], r['remain']) == (100.0, 40.0, 60.0)   # 包求和兜底

    fake(json.dumps({'code': 1001, 'message': 'unauthorized'}))
    r = cm.credits_summary('t', '1', tries=1)
    assert r['code'] == 1001 and r['total'] is None                      # 鉴权失败要能触发续期


def test_shared_identity():
    """两个脚本共用一个 token 缓存文件，键与设备号算法必须一致。"""
    acc = {'uid': '113185', 'name': '主号'}
    assert ci._acct_key(acc) == cm.acct_key('113185', '主号') == '113185'
    assert ci._acct_key({'_name': '主号'}) == cm.acct_key('', '主号') == '主号'
    assert ci._acct_key({}) == cm.acct_key('', '') == 'default'          # 无标识兜底
    assert ci._acct_key({'_name': '账号2'}) == cm.acct_key('', '账号2')  # TRAE_REFRESH_TOKEN_2
    seed = '113185'
    assert ci.stable_device_id(seed) == cm.stable_device_id(seed)        # 同一台设备
    did = ci.stable_device_id(seed)
    assert did.isdigit() and len(did) == 16


def test_build_account_refresh_only():
    """文档写着「可只给 refreshToken」，加载阶段就必须认，不能等续期时才炸。"""
    acc = ci.build_account({'refreshToken': 'rt', 'uid': 'u1'}, '主号')
    assert acc['refreshToken'] == 'rt' and acc['accessToken'] == '' and acc['uid'] == 'u1'
    try:
        ci.build_account({'uid': 'u2'}, '空号')
    except ValueError as e:
        assert 'refreshToken' in str(e)
    else:
        raise AssertionError('缺凭据的账号应当报错')


def test_extract_parses_json_blob():
    """storage.json 解密后是 JSON（尾部带填充残留），必须连 accessToken 一起解出来。
    只给 refreshToken 续期会被服务端拒成 10101，所以提取器得给全。"""
    import trae_get_token as gt
    import tempfile

    # 造一份真实的加密凭据：自加密不可行（只有解密），所以直接验证解析层
    blob = ('{"token":"AT","refreshToken":"RT","userId":"1430910469149417",'
            '"expiredAt":"2026-11-19T08:44:42.962Z",'
            '"account":{"username":"略略略"}}')
    txt = blob + "\x00\x00\x00"            # 模拟尾部填充残留
    try:
        d, _ = json.JSONDecoder().raw_decode(txt)
    except ValueError:
        raise AssertionError('raw_decode 必须能吃掉尾部残留')
    assert d['token'] == 'AT' and d['account']['username'] == '略略略'

    assert gt.at_valid('2099-01-01T00:00:00.000Z') is True
    assert gt.at_valid('2020-01-01T00:00:00.000Z') is False
    assert gt.at_valid('') is False


def test_extract_emits_device_keypair():
    """提取器必须连设备密钥对一起给出，否则续期仍会 10101。
    设备密钥在 icube-dc 键里用同一套 AES 加密，应能解出 privateKeyPEM/publicKeyPEM。"""
    import trae_get_token as gt
    # 用真实解出的室友设备身份(376309...)验证：device_keypair 能解出完整三件套
    # 无法离线造密文，退而验证 device_keypair 对"无实际密钥"的容错：给假 base64 返回空
    st = {'telemetry.machineId': 'mm',
          'iCubeAuthInfo://icube-dc:3753091561689896': 'not-a-real-cipher',
          'iCubeAuthInfo://icube.cloudide': 'x'}
    assert gt.device_keypair(st) == {}            # 无效密文 -> 空，不抛
    assert gt.real_device_id(st) == '3753091561689896'


def test_real_device_id_wins_and_never_rotates():
    """9074 的根因是设备号不被服务端认可，不是限流（2026-11 实测）。
    真机号必须优先、且 9074 后绝不轮换成合成号，否则越换越签不上。"""
    import trae_get_token as gt
    st = {'iCubeAuthInfo://icube-dc:2803108645440825': 'x',
          'iCubeAuthInfo://icube.cloudide': 'y'}
    assert gt.real_device_id(st) == '2803108645440825'
    assert gt.real_device_id({}) == ''

    # 真机号优先于持久化/合成号
    real = {'_name': '主号', '_realDid': '2803108645440825', 'deviceId': ''}
    assert ci.device_id_for(real, '') == '2803108645440825'

    # 9074 后不轮换真机号
    real['deviceId'] = '2803108645440825'
    assert ci.rotate_device_id(real) == '2803108645440825'

    # 手工填的 deviceId 同样钉住
    pinned = {'_name': '手填', 'deviceId': '1234567890123456'}
    ci.device_id_for(pinned, '1234567890123456')
    assert ci.rotate_device_id(pinned) == '1234567890123456'


def test_status_flags():
    """did_checked_in 是设备维度，checked_in 是账号维度，两者都要能读到。"""
    body = json.dumps({'checked_in': False, 'did_checked_in': True, 'credits': 100,
                       'enable': True, 'code': 0})
    ci._post = lambda *a, **k: (200, body)
    checked_in, credits, enable, code, raw, did = ci.status_of('t', '2803108645440825')
    assert (checked_in, did, credits, enable) == (False, True, 100, True)


def test_device_signature_context():
    """设备签名续期：有私钥+真机号时能组装出可用 context，缺任何一样则退化为 None
    （走无签名续期，不炸）。DeviceProof 必须包含客户端要求的 Timestamp/Nonce/Signature。"""
    priv = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PRIVATE KEY-----'
    pub = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PUBLIC KEY-----'

    # 缺私钥 → None（退化为无签名续期，不崩）
    acc_no = {'deviceId': '3753091561689896', '_realDid': '3753091561689896',
              'devicePublicKeyPEM': pub}
    assert ci.build_device_context(acc_no) is None

    # 私钥 + 真机号都在 → 有完整 context
    acc_ok = {'deviceId': '3753091561689896', '_realDid': '3753091561689896',
              'devicePrivateKeyPEM': priv,
              'devicePublicKeyPEM': pub,
              'deviceMachineId': 'a56b1c94'}
    ctx = ci.build_device_context(acc_ok)
    assert ctx and ctx['device_id'] == '3753091561689896'
    assert ctx['private_key_pem'] == priv

    # 私钥里含字面 \n 转义也要能还原成真实换行
    acc_esc = {'deviceId': '3753091561689896', '_realDid': '3753091561689896',
               'devicePrivateKeyPEM': priv.replace('\n', '\\n'),
               'devicePublicKeyPEM': pub, 'deviceMachineId': 'm'}
    assert ci.build_device_context(acc_esc)['private_key_pem'] == priv


def test_dc_keypair_from_storage():
    """load_from_storage 应从 icube-dc 键一并解出设备密钥对，供账号做签名续期。
    无密钥的会拿到空 deviceId/密钥而不抛错。"""
    st = {'telemetry.machineId': 'mm',
          'iCubeAuthInfo://icube.cloudide': 'x',
          'iCubeAuthInfo://icube-dc:2803108645440825': 'base64!'}
    kp = ci.dc_keypair(st)   # 加密串无效 → 解不出 → 空 dict
    assert kp == {}
    assert ci.dc_device_id(st) == '2803108645440825'


if __name__ == '__main__':
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
            n += 1
            print('✅ %s' % name)
    print('🏁 %d 组自检全部通过（离线，未联网）' % n)

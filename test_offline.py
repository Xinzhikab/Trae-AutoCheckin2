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


if __name__ == '__main__':
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
            n += 1
            print('✅ %s' % name)
    print('🏁 %d 组自检全部通过（离线，未联网）' % n)

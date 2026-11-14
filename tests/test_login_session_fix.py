"""验证登录扫码状态机、二次安全验证识别、全域名 Cookie 检测与空闲浏览器回收。"""

from __future__ import annotations

import base64
from io import BytesIO
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image

from core import browser as browser_mod
from core import login_session as ls
from core.executor import executor


def _make_qr_b64(seed: int) -> str:
    """生成带显著黑白像素比的可辨识测试二维码 PNG base64（无 data URL 前缀）。"""
    img = Image.new("RGB", (120, 120), "WHITE")
    for x in range(15):
        for y in range(15):
            if ((x * 7 + y * 13 + seed) % 3) == 0:
                for dx in range(8):
                    for dy in range(8):
                        img.putpixel((x * 8 + dx, y * 8 + dy), (0, 0, 0))
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


class _FakeContext:
    def __init__(self) -> None:
        self.cookie_list: list[dict] = []
        self.saved_states = 0

    def cookies(self):
        return list(self.cookie_list)

    def storage_state(self):
        self.saved_states += 1
        return {"cookies": list(self.cookie_list), "origins": []}


class _FakePage:
    def __init__(self, on_tick=None) -> None:
        self.url = "https://www.douyin.com/chat?isPopup=1"
        self.frames = [self]
        self.main_frame = self
        self._on_tick = on_tick
        self.ticks = 0

    def wait_for_timeout(self, ms: int) -> None:
        self.ticks += 1
        if self._on_tick:
            self._on_tick(self.ticks)


def _setup_session(aid: str, phase: str = "qr_ready", qr_b64: str = "") -> tuple[dict, threading.Event]:
    flag = threading.Event()
    st = ls._new_state(aid, status="waiting_scan", phase=phase, message="请扫码", qrcode=f"data:image/png;base64,{qr_b64}")
    with ls._guard:
        ls._sessions[aid] = st
        ls._stop_flags[aid] = flag
    return st, flag


def _cleanup_session(aid: str) -> None:
    with ls._guard:
        ls._sessions.pop(aid, None)
        ls._stop_flags.pop(aid, None)


class LoginSessionFixTests(unittest.TestCase):
    def test_cookie_expiry_and_cross_domain(self) -> None:
        now = time.time()
        self.assertFalse(ls._has_login_cookie([{"name": "sessionid", "value": "x", "expires": now - 5}]))
        self.assertFalse(ls._has_login_cookie([{"name": "sessionid", "value": "", "expires": -1}]))
        self.assertTrue(ls._has_login_cookie([{"name": "sessionid", "value": "ok", "expires": -1, "domain": ".sso.douyin.com"}]))
        self.assertTrue(ls._has_login_cookie([{"name": "sid_tt", "value": "ok", "expires": now + 3600}]))

    def test_parse_verify_config_header_and_body(self) -> None:
        conf_h = ls._parse_verify_config(
            {"X-Vc-Bdturing-Parameters": '{"code": 10000, "subtype": "slide"}'},
            None,
        )
        self.assertIsNotNone(conf_h)
        self.assertEqual(conf_h["code"], 10000)
        self.assertEqual(conf_h["subtype"], "slide")

        conf_b = ls._parse_verify_config(
            {},
            {"data": {"verify_center_decision_conf": '{"code": 20000, "subtype": "qr_code_verify"}'}},
        )
        self.assertIsNotNone(conf_b)
        self.assertEqual(conf_b["code"], 20000)
        self.assertEqual(conf_b["subtype"], "qr_code_verify")
        self.assertIsNone(ls._map_verify_subtype_to_risk("qr_code_verify", 20000))
        self.assertEqual(ls._map_verify_subtype_to_risk("mobile_sms_verify", 20000), "interactive_sms")

    def test_silent_refresh_syncs_new_qr_and_succeeds(self) -> None:
        aid = "test_silent_refresh"
        qr_a = _make_qr_b64(1)
        qr_b = _make_qr_b64(2)
        _setup_session(aid, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            seen_refreshed = {}

            def on_tick(tick: int) -> None:
                if tick == 1:
                    tracker._ingest_response_data(
                        "https://sso.douyin.com/check_qrconnect/",
                        200,
                        {},
                        {
                            "data": {
                                "status": "expired",
                                "qrcode": qr_b,
                                "token": "tok2",
                                "qrcode_index_url": "https://www.douyin.com/login/tok2",
                            },
                            "message": "success",
                        },
                    )
                elif tick == 2:
                    seen_refreshed.update(ls.status(aid))
                    ctx.cookie_list.append({"name": "sessionid", "value": "sess_ok", "domain": ".sso.douyin.com"})

            page = _FakePage(on_tick=on_tick)
            dom_empty = ls._empty_dom_inspection()
            with mock.patch.object(ls, "_inspect_all_frames", return_value=dom_empty), mock.patch.object(ls, "_save_state") as save_mock:
                ls._poll_until_login(
                    aid,
                    ctx,
                    page,
                    tracker,
                    ls._stop_flags[aid],
                    initial_qr_fp=ls._qr_fingerprint(qr_a),
                    initial_qr=f"data:image/png;base64,{qr_a}",
                )

            save_mock.assert_called_once()
            self.assertEqual(seen_refreshed.get("phase"), "qr_refreshed")
            self.assertEqual(seen_refreshed.get("status"), "waiting_scan")
            self.assertEqual(seen_refreshed.get("deep_link"), "https://www.douyin.com/login/tok2")
            self.assertTrue(seen_refreshed.get("qrcode", "").startswith("data:image/png;base64,"))
            final = ls.status(aid)
            self.assertEqual(final["status"], "success")
            self.assertEqual(final["phase"], "success")
        finally:
            _cleanup_session(aid)

    def test_dom_silent_qr_rotation_updates_once_per_image(self) -> None:
        aid = "test_dom_rotation"
        qr_a = _make_qr_b64(3)
        qr_b = _make_qr_b64(4)
        _setup_session(aid, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            snapshots: list[dict] = []

            def on_tick(tick: int) -> None:
                snapshots.append(ls.status(aid))
                if tick == 3:
                    ctx.cookie_list.append({"name": "sid_guard", "value": "g1"})

            page = _FakePage(on_tick=on_tick)
            dom_rot = {**ls._empty_dom_inspection(), "loginQrSrc": f"data:image/png;base64,{qr_b}"}
            with mock.patch.object(ls, "_inspect_all_frames", return_value=dom_rot), mock.patch.object(ls, "_save_state"):
                ls._poll_until_login(
                    aid,
                    ctx,
                    page,
                    tracker,
                    ls._stop_flags[aid],
                    initial_qr_fp=ls._qr_fingerprint(qr_a),
                    initial_qr=f"data:image/png;base64,{qr_a}",
                )

            self.assertEqual(snapshots[0]["phase"], "qr_refreshed")
            self.assertIn("第 1 次", snapshots[0]["message"])
            self.assertIn("第 1 次", snapshots[1]["message"])
            self.assertEqual(ls.status(aid)["status"], "success")
        finally:
            _cleanup_session(aid)

    def test_scanned_and_confirmed_transitions_hide_stale_qr_until_success(self) -> None:
        aid = "test_scanned_confirmed"
        qr_a = _make_qr_b64(5)
        _setup_session(aid, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            snapshots: list[dict] = []

            def on_tick(tick: int) -> None:
                if tick == 1:
                    tracker._ingest_response_data(
                        "https://sso.douyin.com/check_qrconnect/",
                        200,
                        {},
                        {"data": {"status": "scanned", "scan_device_info": {"device_name": "iPhone 15"}}},
                    )
                elif tick == 2:
                    snapshots.append(ls.status(aid))
                    tracker._ingest_response_data(
                        "https://sso.douyin.com/check_qrconnect/",
                        200,
                        {},
                        {"data": {"status": "confirmed", "redirect_url": "https://sso.douyin.com/cb"}},
                    )
                elif tick == 3:
                    snapshots.append(ls.status(aid))
                    ctx.cookie_list.append({"name": "uid_tt", "value": "u123", "domain": ".douyin.com"})

            page = _FakePage(on_tick=on_tick)
            with mock.patch.object(ls, "_inspect_all_frames", return_value=ls._empty_dom_inspection()), mock.patch.object(ls, "_save_state"):
                ls._poll_until_login(
                    aid,
                    ctx,
                    page,
                    tracker,
                    ls._stop_flags[aid],
                    initial_qr_fp=ls._qr_fingerprint(qr_a),
                    initial_qr=f"data:image/png;base64,{qr_a}",
                )

            self.assertEqual(snapshots[0]["phase"], "scanned")
            self.assertEqual(snapshots[0]["qrcode"], "")
            self.assertEqual(snapshots[0]["scan_device"], "iPhone 15")
            self.assertIn("iPhone 15", snapshots[0]["message"])

            self.assertEqual(snapshots[1]["phase"], "confirmed")
            self.assertEqual(snapshots[1]["qrcode"], "")
            self.assertIn("已确认", snapshots[1]["message"])
            self.assertEqual(ls.status(aid)["status"], "success")
        finally:
            _cleanup_session(aid)

    def test_secondary_verify_qr_without_face_button_pushes_qr_and_clicks_done(self) -> None:
        aid = "test_second_verify_direct_qr"
        qr_a = _make_qr_b64(6)
        qr_sec = _make_qr_b64(7)
        _setup_session(aid, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            tracker._ingest_response_data(
                "https://www.douyin.com/passport/safe/verify",
                200,
                {},
                {"data": {"verify_center_decision_conf": '{"code": 20000, "subtype": "qr_code_verify"}'}},
            )
            pushed_second = {}
            fake_sec_frame = object()

            def on_tick(tick: int) -> None:
                if tick == 1:
                    pushed_second.update(ls.status(aid))
                elif tick == 2:
                    ctx.cookie_list.append({"name": "sessionid_ss", "value": "sec_ok", "domain": ".douyin.com"})

            page = _FakePage(on_tick=on_tick)
            dom_sec = {
                **ls._empty_dom_inspection(),
                "secVisible": True,
                "secQr": f"data:image/png;base64,{qr_sec}",
                "hasFaceChoice": False,
                "hasDoneBtn": True,
                "secFrame": fake_sec_frame,
            }
            with (
                mock.patch.object(ls, "_inspect_all_frames", return_value=dom_sec),
                mock.patch.object(ls, "_js_click_first", return_value=True) as click_mock,
                mock.patch.object(ls, "_save_state") as save_mock,
            ):
                ls._poll_until_login(
                    aid,
                    ctx,
                    page,
                    tracker,
                    ls._stop_flags[aid],
                    initial_qr_fp=ls._qr_fingerprint(qr_a),
                    initial_qr=f"data:image/png;base64,{qr_a}",
                )

            self.assertEqual(pushed_second["phase"], "second_verify_qr")
            self.assertTrue(pushed_second["qrcode"].startswith("data:image/png;base64,"))
            click_mock.assert_called_with(
                fake_sec_frame,
                ["我已完成验证", "已完成验证", "验证成功", "已完成"],
                exact_only={"已完成"},
            )
            save_mock.assert_called_once()
            self.assertEqual(ls.status(aid)["status"], "success")
        finally:
            _cleanup_session(aid)

    def test_interactive_sms_fast_fails_without_clicking_done(self) -> None:
        aid = "test_sms_block"
        qr_a = _make_qr_b64(8)
        _setup_session(aid, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            page = _FakePage()
            dom_sms = {
                **ls._empty_dom_inspection(),
                "secVisible": True,
                "secText": "安全验证 发送短信验证 我已完成短信发送",
                "interactiveType": "sms",
                "hasFaceChoice": False,
                "hasDoneBtn": False,
            }
            with (
                mock.patch.object(ls, "_inspect_all_frames", return_value=dom_sms),
                mock.patch.object(ls, "_js_click_first") as click_mock,
            ):
                with self.assertRaises(ls._RiskControlError) as cm:
                    ls._poll_until_login(
                        aid,
                        ctx,
                        page,
                        tracker,
                        ls._stop_flags[aid],
                        initial_qr_fp=ls._qr_fingerprint(qr_a),
                        initial_qr=f"data:image/png;base64,{qr_a}",
                    )
            self.assertEqual(cm.exception.error_code, "sms_verify_required")
            click_mock.assert_not_called()
            self.assertLessEqual(page.ticks, 3)
        finally:
            _cleanup_session(aid)

    def test_hidden_nocaptcha_ignored_while_visible_captcha_frame_triggers(self) -> None:
        class _FakeFrameEl:
            def __init__(self, vis: bool, w: int, h: int) -> None:
                self._vis = vis
                self._w = w
                self._h = h

            def is_visible(self) -> bool:
                return self._vis

            def bounding_box(self) -> dict:
                return {"x": 0, "y": 0, "width": self._w, "height": self._h}

        class _FakeChildFrame:
            def __init__(self, url: str, el: _FakeFrameEl) -> None:
                self.url = url
                self._el = el

            def frame_element(self):
                return self._el

            def evaluate(self, js):
                return None

        class _FakeMainPage:
            def __init__(self, frames) -> None:
                self.main_frame = self
                self.frames = [self, *frames]

            def evaluate(self, js):
                return {k: v for k, v in ls._empty_dom_inspection().items() if k != "secFrame"}

        hidden_nocaptcha = _FakeChildFrame(
            "https://lf-rc1.yhgfb-cn-static.com/obj/rc-verifycenter/rmc-nocaptcha/index.html",
            _FakeFrameEl(False, 0, 0),
        )
        res_hidden = ls._inspect_all_frames(_FakeMainPage([hidden_nocaptcha]))
        self.assertFalse(res_hidden["captchaVisible"])

        visible_captcha = _FakeChildFrame(
            "https://rmc.bytedance.com/verifycenter/captcha/v2?aid=6383",
            _FakeFrameEl(True, 340, 280),
        )
        res_vis = ls._inspect_all_frames(_FakeMainPage([visible_captcha]))
        self.assertTrue(res_vis["captchaVisible"])

    def test_qr_refused_and_confirmed_api_error(self) -> None:
        aid = "test_refused"
        qr_a = _make_qr_b64(9)
        _setup_session(aid, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            tracker._ingest_response_data(
                "https://sso.douyin.com/check_qrconnect/",
                200,
                {},
                {"data": {"status": "4"}},
            )
            page = _FakePage()
            with mock.patch.object(ls, "_inspect_all_frames", return_value=ls._empty_dom_inspection()):
                with self.assertRaises(ls._RiskControlError) as cm:
                    ls._poll_until_login(
                        aid,
                        ctx,
                        page,
                        tracker,
                        ls._stop_flags[aid],
                        initial_qr_fp=ls._qr_fingerprint(qr_a),
                        initial_qr=f"data:image/png;base64,{qr_a}",
                    )
            self.assertEqual(cm.exception.error_code, "qr_refused")
        finally:
            _cleanup_session(aid)

        # Confirmed stall + Douyin error_code
        aid2 = "test_confirmed_err"
        _setup_session(aid2, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            tracker._ingest_response_data(
                "https://sso.douyin.com/check_qrconnect/",
                200,
                {},
                {"data": {"status": "confirmed", "error_code": 1105, "description": "账号异常拦截"}},
            )
            tracker.confirmed_at = time.time() - 50
            page = _FakePage()
            with mock.patch.object(ls, "_inspect_all_frames", return_value=ls._empty_dom_inspection()):
                with self.assertRaises(ls._RiskControlError) as cm:
                    ls._poll_until_login(
                        aid2,
                        ctx,
                        page,
                        tracker,
                        ls._stop_flags[aid2],
                        initial_qr_fp=ls._qr_fingerprint(qr_a),
                        initial_qr=f"data:image/png;base64,{qr_a}",
                    )
            self.assertEqual(cm.exception.error_code, "douyin_error_1105")
            self.assertIn("账号异常拦截", cm.exception.message)
        finally:
            _cleanup_session(aid2)

    def test_reclaim_idle_from_executor_only_closes_idle_on_worker_thread(self) -> None:
        class _FakePooledBrowser:
            def __init__(self) -> None:
                self.closed_on_tid = None

            def close(self) -> None:
                self.closed_on_tid = threading.get_ident()

        with browser_mod._POOL_LOCK:
            saved_pool = dict(browser_mod._BROWSER_POOL)
            browser_mod._BROWSER_POOL.clear()

        try:
            # Empty pool -> 0 without touching executor
            self.assertEqual(browser_mod.reclaim_idle_from_executor(), 0)

            idle_b = _FakePooledBrowser()
            active_b = _FakePooledBrowser()
            with browser_mod._POOL_LOCK:
                browser_mod._BROWSER_POOL["idle"] = {"browser": idle_b, "refs": 0, "last_used": time.time()}
                browser_mod._BROWSER_POOL["active"] = {"browser": active_b, "refs": 1, "last_used": time.time()}

            reclaimed = browser_mod.reclaim_idle_from_executor(force=True, timeout=3.0)
            self.assertEqual(reclaimed, 1)
            self.assertEqual(idle_b.closed_on_tid, executor._thread.ident)
            self.assertIsNone(active_b.closed_on_tid)
            with browser_mod._POOL_LOCK:
                self.assertNotIn("idle", browser_mod._BROWSER_POOL)
                self.assertIn("active", browser_mod._BROWSER_POOL)
        finally:
            with browser_mod._POOL_LOCK:
                browser_mod._BROWSER_POOL.clear()
                browser_mod._BROWSER_POOL.update(saved_pool)

    def test_acquire_initial_qr_paths_and_risk_fast_fail(self) -> None:
        qr_a = _make_qr_b64(10)
        qr_b = _make_qr_b64(11)

        # 1) DOM 已有码时走快路径，并复用网络 get_qrcode 的 deep_link
        tracker1 = ls._LoginNetworkTracker()
        tracker1._ingest_response_data(
            "https://sso.douyin.com/get_qrcode/",
            200,
            {},
            {"data": {"qrcode": qr_a, "qrcode_index_url": "https://www.douyin.com/login/dl1", "token": "t1"}},
        )
        page1 = _FakePage()
        dom1 = {**ls._empty_dom_inspection(), "loginQrSrc": f"data:image/png;base64,{qr_a}"}
        with mock.patch.object(ls, "_inspect_all_frames", return_value=dom1):
            enh, dl, fp, phase = ls._acquire_initial_qr(page1, "aid_init_dom", threading.Event(), tracker1, timeout_s=5.0)
        self.assertEqual(phase, "qr_ready")
        self.assertEqual(dl, "https://www.douyin.com/login/dl1")
        self.assertEqual(fp, ls._qr_fingerprint(qr_a))
        self.assertTrue(enh.startswith("data:image/png;base64,"))
        self.assertEqual(page1.ticks, 0)

        # 2) DOM 未渲染但网络 get_qrcode 已拿码，超过 1.2s 直接兜底返回
        tracker2 = ls._LoginNetworkTracker()
        tracker2._ingest_response_data(
            "https://sso.douyin.com/get_qrcode/",
            200,
            {},
            {"data": {"qrcode": qr_b, "qrcode_index_url": "https://www.douyin.com/login/dl2", "token": "t2"}},
        )
        page2 = _FakePage(on_tick=lambda _tick: time.sleep(0.35))
        with mock.patch.object(ls, "_inspect_all_frames", return_value=ls._empty_dom_inspection()):
            enh2, dl2, fp2, phase2 = ls._acquire_initial_qr(page2, "aid_init_net", threading.Event(), tracker2, timeout_s=5.0)
        self.assertEqual(phase2, "qr_ready")
        self.assertEqual(dl2, "https://www.douyin.com/login/dl2")
        self.assertEqual(fp2, ls._qr_fingerprint(qr_b))
        self.assertTrue(enh2.startswith("data:image/png;base64,"))

        # 3) 启动期连续 3 次检测到可见验证码 -> 快速失败（slider_captcha）
        tracker3 = ls._LoginNetworkTracker()
        page3 = _FakePage()
        dom_cap = {**ls._empty_dom_inspection(), "captchaVisible": True, "captchaHint": "#vc_captcha_wrapper"}
        with mock.patch.object(ls, "_inspect_all_frames", return_value=dom_cap):
            with self.assertRaises(ls._RiskControlError) as cm:
                ls._acquire_initial_qr(page3, "aid_init_cap", threading.Event(), tracker3, timeout_s=5.0)
        self.assertEqual(cm.exception.error_code, "slider_captcha")
        self.assertEqual(page3.ticks, 2)

        # 4) 取消标志置位 -> 立即抛出 CancelledError
        stop_ev = threading.Event()
        stop_ev.set()
        with self.assertRaises(ls.CancelledError):
            ls._acquire_initial_qr(_FakePage(), "aid_init_cancel", stop_ev, ls._LoginNetworkTracker(), timeout_s=5.0)

    def test_secondary_verify_face_choice_and_qr_expired_refresh(self) -> None:
        aid = "test_second_verify_refresh"
        qr_a = _make_qr_b64(12)
        qr_sec1 = _make_qr_b64(13)
        qr_sec2 = _make_qr_b64(14)
        _setup_session(aid, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            fake_sec_frame = object()
            dom_holder = {
                "dom": {
                    **ls._empty_dom_inspection(),
                    "secVisible": True,
                    "hasFaceChoice": True,
                    "secQr": "",
                    "secFrame": fake_sec_frame,
                }
            }
            seen_states: list[dict] = []

            def on_tick(tick: int) -> None:
                seen_states.append(ls.status(aid))
                if tick == 1:
                    # 点击刷脸/扫码入口后，弹窗出现首张二次验证二维码
                    dom_holder["dom"] = {
                        **ls._empty_dom_inspection(),
                        "secVisible": True,
                        "hasFaceChoice": False,
                        "secQr": f"data:image/png;base64,{qr_sec1}",
                        "hasDoneBtn": False,
                        "secFrame": fake_sec_frame,
                    }
                elif tick == 2:
                    # 二次验证二维码过期，出现刷新按钮
                    dom_holder["dom"] = {
                        **ls._empty_dom_inspection(),
                        "secVisible": True,
                        "hasRefreshBtn": True,
                        "secQr": f"data:image/png;base64,{qr_sec1}",
                        "secFrame": fake_sec_frame,
                    }
                elif tick == 3:
                    # 刷新点击后换出第二张二次验证二维码 + 我已完成验证按钮
                    dom_holder["dom"] = {
                        **ls._empty_dom_inspection(),
                        "secVisible": True,
                        "hasRefreshBtn": False,
                        "hasDoneBtn": True,
                        "secQr": f"data:image/png;base64,{qr_sec2}",
                        "secFrame": fake_sec_frame,
                    }
                elif tick == 4:
                    ctx.cookie_list.append({"name": "sessionid", "value": "sec_refreshed_ok", "domain": ".douyin.com"})

            page = _FakePage(on_tick=on_tick)
            with (
                mock.patch.object(ls, "_inspect_all_frames", side_effect=lambda _p: dom_holder["dom"]),
                mock.patch.object(ls, "_js_click_first", return_value=True) as click_mock,
                mock.patch.object(ls, "_click_second_verify_refresh", return_value=True) as refresh_mock,
                mock.patch.object(ls, "_save_state") as save_mock,
            ):
                ls._poll_until_login(
                    aid,
                    ctx,
                    page,
                    tracker,
                    ls._stop_flags[aid],
                    initial_qr_fp=ls._qr_fingerprint(qr_a),
                    initial_qr=f"data:image/png;base64,{qr_a}",
                )

            click_mock.assert_any_call(fake_sec_frame, ["手机刷脸验证", "刷脸验证", "扫码验证", "抖音App扫码验证"])
            click_mock.assert_any_call(
                fake_sec_frame,
                ["我已完成验证", "已完成验证", "验证成功", "已完成"],
                exact_only={"已完成"},
            )
            refresh_mock.assert_called_once_with(fake_sec_frame)
            save_mock.assert_called_once()
            self.assertEqual(seen_states[1]["phase"], "second_verify_qr")
            self.assertEqual(seen_states[3]["phase"], "second_verify_qr")
            self.assertNotEqual(seen_states[1]["qrcode"], seen_states[3]["qrcode"])
            self.assertEqual(ls.status(aid)["status"], "success")
        finally:
            _cleanup_session(aid)

    def test_reclaim_idle_from_executor_timeout_sets_cancelled_guard(self) -> None:
        class _FakePooledBrowser:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

        with browser_mod._POOL_LOCK:
            saved_pool = dict(browser_mod._BROWSER_POOL)
            browser_mod._BROWSER_POOL.clear()

        gate = threading.Event()
        entered = threading.Event()
        try:
            idle_b = _FakePooledBrowser()
            with browser_mod._POOL_LOCK:
                browser_mod._BROWSER_POOL["idle"] = {"browser": idle_b, "refs": 0, "last_used": time.time()}

            def _blocker() -> None:
                entered.set()
                gate.wait(timeout=3.0)

            executor.submit(_blocker)
            self.assertTrue(entered.wait(timeout=2.0))

            reclaimed = browser_mod.reclaim_idle_from_executor(force=True, timeout=0.05)
            self.assertEqual(reclaimed, 0)
        finally:
            gate.set()
            executor.submit_and_wait(lambda: None, timeout=3.0)
            try:
                self.assertFalse(idle_b.closed)
                with browser_mod._POOL_LOCK:
                    self.assertIn("idle", browser_mod._BROWSER_POOL)
            finally:
                with browser_mod._POOL_LOCK:
                    browser_mod._BROWSER_POOL.clear()
                    browser_mod._BROWSER_POOL.update(saved_pool)

    def test_network_tracker_headers_numeric_statuses_and_confirmed_timeout(self) -> None:
        class _FakeResp:
            def __init__(self, url: str, headers: dict, json_exc: Exception | None = None) -> None:
                self.url = url
                self.headers = headers
                self.status = 200
                self._exc = json_exc

            def json(self):
                if self._exc:
                    raise self._exc
                return {}

        tracker = ls._LoginNetworkTracker()
        # 非 JSON HTML 响应携带 bdturing-verify 响应头时不得抛异常且应解析 verify_event
        tracker.on_response(
            _FakeResp(
                "https://www.douyin.com/chat?isPopup=1",
                {"bdturing-verify": '{"code": 10000, "subtype": "slide"}'},
                json_exc=ValueError("not json"),
            )
        )
        snap = tracker.snapshot()
        self.assertIsNotNone(snap["verify_event"])
        self.assertEqual(snap["verify_event"]["code"], 10000)

        # 数字态状态码与 safe/get_qrcode 分流
        qr_sec = _make_qr_b64(15)
        tracker._ingest_response_data(
            "https://www.douyin.com/passport/safe/get_qrcode/",
            200,
            {},
            {"data": {"qrcode": qr_sec, "qrcode_index_url": "https://www.douyin.com/safe/1"}},
        )
        self.assertEqual(tracker.pop_pending_second_qr(), (qr_sec, "https://www.douyin.com/safe/1", "safe_get_qrcode"))
        self.assertIsNone(tracker.pop_pending_qr())

        tracker._ingest_response_data("https://sso.douyin.com/check_qrconnect/", 200, {}, {"data": {"status": "5"}})
        self.assertTrue(tracker.snapshot()["qr_needs_manual_refresh"])

        # confirmed 阶段超时但无 api_error 时应礼貌转为 expired（提示凭证同步超时）
        aid = "test_confirmed_timeout"
        qr_a = _make_qr_b64(16)
        _setup_session(aid, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            t2 = ls._LoginNetworkTracker()
            t2._ingest_response_data("https://sso.douyin.com/check_qrconnect/", 200, {}, {"data": {"status": "3"}})
            page = _FakePage()
            with (
                mock.patch.object(ls, "SESSION_TIMEOUT", 0.05),
                mock.patch.object(ls, "_inspect_all_frames", return_value=ls._empty_dom_inspection()),
            ):
                ls._poll_until_login(
                    aid,
                    ctx,
                    page,
                    t2,
                    ls._stop_flags[aid],
                    initial_qr_fp=ls._qr_fingerprint(qr_a),
                    initial_qr=f"data:image/png;base64,{qr_a}",
                )
            final = ls.status(aid)
            self.assertEqual(final["status"], "expired")
            self.assertIn("凭证同步超时", final["message"])
        finally:
            _cleanup_session(aid)

    def test_inspect_frame_js_chromium_dom_smoke(self) -> None:
        if ls.sync_playwright is None:
            self.skipTest("playwright unavailable")

        qr_login = f"data:image/png;base64,{_make_qr_b64(17)}"
        qr_sec = f"data:image/png;base64,{_make_qr_b64(18)}"

        with ls.sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 800})
                page.route(
                    "**/*",
                    lambda route: route.fulfill(status=200, content_type="text/html", body="<html><body></body></html>")
                    if route.request.url.startswith("http")
                    else route.continue_(),
                )

                # 1) 初始登录码 + 隐藏 0x0 rmc-nocaptcha iframe（不得误报验证码）
                page.set_content(
                    f"""
                    <html><body>
                      <div id="douyin_login_comp_flat_panel">
                        <div id="animate_qrcode_container">
                          <img src="{qr_login}" style="width:160px;height:160px;display:block;" />
                        </div>
                      </div>
                      <iframe src="https://lf-rc1.yhgfb-cn-static.com/obj/rc-verifycenter/rmc-nocaptcha/index.html"
                              style="width:0;height:0;display:none;border:0;"></iframe>
                    </body></html>
                    """
                )
                res1 = ls._inspect_all_frames(page)
                self.assertTrue(res1["loginQrSrc"].startswith("data:image/png;base64,"))
                self.assertFalse(res1["loginQrExpired"])
                self.assertFalse(res1["captchaVisible"])
                self.assertFalse(res1["secVisible"])

                # 2) 可见滑块验证码容器应命中 captchaVisible
                page.set_content(
                    """
                    <html><body>
                      <div id="vc_captcha_wrapper" style="width:340px;height:240px;display:block;">
                        请完成拼图验证
                      </div>
                    </body></html>
                    """
                )
                res2 = ls._inspect_all_frames(page)
                self.assertTrue(res2["captchaVisible"])

                # 3) 二次验证扫码弹窗 (.vc-second-valid-mask) 应隔离登录框二维码并识别「我已完成验证」
                page.set_content(
                    f"""
                    <html><body>
                      <div id="animate_qrcode_container">
                        <img src="{qr_login}" style="width:160px;height:160px;display:block;" />
                      </div>
                      <div class="vc-second-valid-mask" style="width:400px;height:360px;display:block;">
                        <div>请使用抖音APP扫一扫完成身份验证</div>
                        <div class="scan-container">
                          <img src="{qr_sec}" style="width:180px;height:180px;display:block;" />
                        </div>
                        <button>我已完成验证</button>
                      </div>
                    </body></html>
                    """
                )
                res3 = ls._inspect_all_frames(page)
                self.assertTrue(res3["secVisible"])
                self.assertEqual(res3["secQr"], qr_sec)
                self.assertTrue(res3["hasDoneBtn"])
                self.assertEqual(res3["interactiveType"], "")

                # 4) 短信验证弹窗包含「我已完成短信发送」时：识别 interactiveType='sms' 且禁止误触发 hasDoneBtn
                page.set_content(
                    """
                    <html><body>
                      <div class="vc-second-valid-mask" style="width:400px;height:360px;display:block;">
                        <div>安全验证：请使用绑定手机发送短信验证</div>
                        <button>我已完成短信发送</button>
                      </div>
                    </body></html>
                    """
                )
                res4 = ls._inspect_all_frames(page)
                self.assertTrue(res4["secVisible"])
                self.assertEqual(res4["interactiveType"], "sms")
                self.assertFalse(res4["hasDoneBtn"])
            finally:
                browser.close()


    def test_manual_expired_overlay_with_mounted_img_syncs_fp_and_drains_network(self) -> None:
        aid = "test_manual_expired_mounted"
        qr_old = _make_qr_b64(20)
        qr_new = _make_qr_b64(21)
        enh_new, _, _ = ls._enhance_qr_image(f"data:image/png;base64,{qr_new}")
        _setup_session(aid, qr_b64=qr_old)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            dom_holder = {
                "dom": {
                    **ls._empty_dom_inspection(),
                    "loginQrSrc": f"data:image/png;base64,{qr_old}",
                    "loginQrExpired": True,
                }
            }
            seen_states: list[dict] = []

            def fake_click_refresh(_page) -> None:
                # 模拟点击页面刷新后，网络端同步收到 get_qrcode 新码且 DOM 切换为新码
                tracker._ingest_response_data(
                    "https://sso.douyin.com/get_qrcode/",
                    200,
                    {},
                    {"data": {"qrcode": qr_new, "qrcode_index_url": "https://www.douyin.com/dl_new"}},
                )
                dom_holder["dom"] = {
                    **ls._empty_dom_inspection(),
                    "loginQrSrc": f"data:image/png;base64,{qr_new}",
                    "loginQrExpired": False,
                }

            def on_tick(tick: int) -> None:
                seen_states.append(ls.status(aid))
                if tick == 2:
                    ctx.cookie_list.append({"name": "sessionid", "value": "manual_refresh_ok", "domain": ".douyin.com"})

            page = _FakePage(on_tick=on_tick)
            with (
                mock.patch.object(ls, "_inspect_all_frames", side_effect=lambda _p: dom_holder["dom"]),
                mock.patch.object(ls, "_click_qr_refresh", side_effect=fake_click_refresh) as click_mock,
                mock.patch.object(
                    ls,
                    "_extract_valid_qrcode",
                    return_value=(enh_new, "https://www.douyin.com/dl_new"),
                ) as extract_mock,
                mock.patch.object(ls, "_save_state") as save_mock,
            ):
                ls._poll_until_login(
                    aid,
                    ctx,
                    page,
                    tracker,
                    ls._stop_flags[aid],
                    initial_qr_fp=ls._qr_fingerprint(qr_old),
                    initial_qr=f"data:image/png;base64,{qr_old}",
                )

            click_mock.assert_called_once_with(page)
            extract_mock.assert_called_once()
            save_mock.assert_called_once()
            # 刷新同周期内的 get_qrcode 应被清空，不触发二次静默换码，且 enh_new 不重复触发 DOM 换码
            self.assertIsNone(tracker.pop_pending_qr())
            self.assertEqual(seen_states[0]["qrcode"], enh_new)
            self.assertEqual(seen_states[0]["phase"], "qr_refreshed")
            self.assertEqual(seen_states[1]["phase"], "qr_refreshed")
            self.assertEqual(ls.status(aid)["status"], "success")
        finally:
            _cleanup_session(aid)

    def test_slot_token_hard_expire_and_stop_flag_race_isolation(self) -> None:
        aid = "test_race_isolation"
        st1, stop1 = _setup_session(aid, qr_b64=_make_qr_b64(22))
        token1 = (aid, next(ls._slot_seq))
        st1["_slot_token"] = token1
        st1["_stop_flag"] = stop1

        token2 = (aid, next(ls._slot_seq))
        stop2 = threading.Event()
        st2 = ls._new_state(
            aid,
            status="waiting_scan",
            phase="qr_ready",
            message="session2",
            _slot_token=token2,
            _stop_flag=stop2,
        )
        acquired_tokens: list = []
        try:
            with (
                mock.patch.object(ls, "acquire_browser_slot") as acq_mock,
                mock.patch.object(ls, "release_browser_slot") as rel_mock,
            ):
                ls._acquire_slot_tracked(token2)
                acquired_tokens.append(token2)
                self.assertEqual(acq_mock.call_count, 1)
                self.assertIn(token2, ls._slot_holders)

                with ls._guard:
                    ls._sessions[aid] = st2
                    ls._stop_flags[aid] = stop2

                # 旧会话的硬超时触发器不得误杀新会话或释放名额
                ls._hard_expire(aid, target_st=st1)
                self.assertFalse(stop2.is_set())
                self.assertIs(ls._sessions[aid], st2)
                self.assertIs(ls._stop_flags[aid], stop2)
                self.assertEqual(st2["status"], "waiting_scan")
                self.assertEqual(rel_mock.call_count, 0)

                # 旧 _session_worker 在取消后退出 finally 时，不得 pop 新会话的 _stop_flags[aid] 或覆盖 st2，且仅释放 token1
                stop1.set()
                fake_pw_cm = mock.MagicMock()
                fake_pw_cm.start.return_value = mock.MagicMock()
                with (
                    mock.patch.object(browser_mod, "reclaim_idle_from_executor", return_value=0),
                    mock.patch.object(ls, "sync_playwright", return_value=fake_pw_cm),
                    mock.patch.object(ls, "_launch_browser", side_effect=ls.CancelledError()),
                ):
                    ls._session_worker(aid, stop1, st=st1)

                self.assertEqual(acq_mock.call_count, 2)
                self.assertEqual(rel_mock.call_count, 1)
                self.assertNotIn(token1, ls._slot_holders)
                self.assertIn(token2, ls._slot_holders)
                self.assertIs(ls._sessions[aid], st2)
                self.assertIs(ls._stop_flags[aid], stop2)

                # _release_slot_once 具备幂等性，重复释放只调用底层 release_browser_slot 一次
                ls._release_slot_once(token2)
                acquired_tokens.remove(token2)
                ls._release_slot_once(token2)
                self.assertEqual(rel_mock.call_count, 2)
                self.assertNotIn(token2, ls._slot_holders)
        finally:
            with ls._slot_guard:
                for tok in acquired_tokens:
                    ls._slot_holders.discard(tok)
                ls._slot_holders.discard(token1)
            _cleanup_session(aid)

    def test_secondary_sms_face_coexistence_refresh_limit_and_deep_link_whitelist(self) -> None:
        # 1) 深链白名单校验
        self.assertTrue(ls._is_allowed_deep_link("https://www.douyin.com/login/scan"))
        self.assertTrue(ls._is_allowed_deep_link("https://sso.douyin.com/check?a=1"))
        self.assertTrue(ls._is_allowed_deep_link("snssdk1128://login"))
        self.assertTrue(ls._is_allowed_deep_link("douyin://login"))
        self.assertFalse(ls._is_allowed_deep_link("javascript:alert(1)"))
        self.assertFalse(ls._is_allowed_deep_link("http://www.douyin.com/insecure"))
        self.assertFalse(ls._is_allowed_deep_link("https://evil.com/douyin.com"))
        self.assertFalse(ls._is_allowed_deep_link(""))

        # 2) hasFaceChoice + interactiveType="sms" 共存时：先点一次刷脸入口；若仍为短信验证则快速失败
        aid1 = "test_sms_face_coexist"
        qr_a = _make_qr_b64(23)
        _setup_session(aid1, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            fake_frame = object()
            dom_sms_and_face = {
                **ls._empty_dom_inspection(),
                "secVisible": True,
                "hasFaceChoice": True,
                "interactiveType": "sms",
                "secFrame": fake_frame,
            }
            page = _FakePage()
            with (
                mock.patch.object(ls, "_inspect_all_frames", return_value=dom_sms_and_face),
                mock.patch.object(ls, "_js_click_first", return_value=True) as click_mock,
            ):
                with self.assertRaises(ls._RiskControlError) as cm:
                    ls._poll_until_login(
                        aid1,
                        ctx,
                        page,
                        tracker,
                        ls._stop_flags[aid1],
                        initial_qr_fp=ls._qr_fingerprint(qr_a),
                        initial_qr=f"data:image/png;base64,{qr_a}",
                    )
            self.assertEqual(cm.exception.error_code, "sms_verify_required")
            click_mock.assert_called_once_with(fake_frame, ["手机刷脸验证", "刷脸验证", "扫码验证", "抖音App扫码验证"])
        finally:
            _cleanup_session(aid1)

        # 3) 二次安全验证二维码刷新达到上限 -> 抛出 _SessionExpiredError
        aid2 = "test_sec_refresh_limit"
        _setup_session(aid2, qr_b64=qr_a)
        try:
            ctx = _FakeContext()
            tracker = ls._LoginNetworkTracker()
            fake_frame = object()
            dom_refresh = {
                **ls._empty_dom_inspection(),
                "secVisible": True,
                "hasRefreshBtn": True,
                "secQr": f"data:image/png;base64,{_make_qr_b64(24)}",
                "secFrame": fake_frame,
            }

            def on_tick_limit(tick: int) -> None:
                if tick > ls.QR_REFRESH_LIMIT + 5:
                    raise AssertionError("secondary verify refresh did not terminate at limit")

            page2 = _FakePage(on_tick=on_tick_limit)
            with (
                mock.patch.object(ls, "_inspect_all_frames", return_value=dom_refresh),
                mock.patch.object(ls, "_click_second_verify_refresh", return_value=True) as sec_ref_mock,
            ):
                with self.assertRaises(ls._SessionExpiredError):
                    ls._poll_until_login(
                        aid2,
                        ctx,
                        page2,
                        tracker,
                        ls._stop_flags[aid2],
                        initial_qr_fp=ls._qr_fingerprint(qr_a),
                        initial_qr=f"data:image/png;base64,{qr_a}",
                    )
            self.assertGreaterEqual(sec_ref_mock.call_count, 1)
            self.assertLessEqual(sec_ref_mock.call_count, ls.QR_REFRESH_LIMIT)
        finally:
            _cleanup_session(aid2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

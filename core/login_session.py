"""网页端扫码登录会话管理。

扫码登录流程：

1. start(account_id)   为账号启动专属无头 Chromium（占用全局并发名额，启动前先请求
                       executor 回收空闲池化浏览器释放内存），打开抖音并唤起登录二维码；
2. status(account_id)  前端轮询：返回当前状态、细分阶段（phase）与最新二维码 data URL；
3. 被动网络与多 Frame   监听 get_qrcode / check_qrconnect / verifycenter / passport/safe
   状态同步            响应与可见 iframe DOM：实时感知静默自动刷新、手机已扫码、已确认、
                       二次安全验证二维码以及无法在云端自动完成的短信/滑块风控；
4. 成功检测            扫描 BrowserContext 全域 Cookie（覆盖 .douyin.com / sso.douyin.com 等）
                       出现 sessionid 等登录凭证即保存 state.json 并清理浏览器；
5. cancel / GC         支持手动取消；整体超时自动回收，防浏览器泄漏。
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import logging
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

from .accounts import acquire_browser_slot, release_browser_slot
from .config import DEFAULT_ACCOUNT_ID, ROOT_STATE_PATH, account_state_path

logger = logging.getLogger("douyin-cloud-streak")

CHAT_URL = "https://www.douyin.com/chat?isPopup=1"

# 扫码等待总时长：覆盖"掏手机 -> 打开抖音 -> 扫码 -> 确认/二次验证"的完整动作
SESSION_TIMEOUT = 300
# 二维码显式/二次验证刷新次数上限
QR_REFRESH_LIMIT = 5

# 登录成功判定 Cookie：覆盖抖音各端变体（sid_guard/sid_tt/uid_tt 与 sessionid 同批下发）
_LOGIN_COOKIE_NAMES = {"sessionid", "sessionid_ss", "sid_tt", "sid_guard", "uid_tt"}

_QR_SELECTORS = [
    "#animate_qrcode_container img",
    '[data-e2e="login-qrcode"] img',
    'div[class*="qrcode"] img',
]

_SLIDER_TEXTS = (
    "拖动滑块",
    "拖动下方滑块",
    "向右拖动",
    "滑块填充拼图",
    "完成拼图",
    "请按顺序点击",
    "请点击下图",
    "旋转图片",
    "使图片角度为正",
    "请在下方图中选出",
)

_QR_STATUS_MAP = {
    "1": "new",
    "new": "new",
    "init": "new",
    "2": "scanned",
    "scanned": "scanned",
    "3": "confirmed",
    "confirmed": "confirmed",
    "4": "refused",
    "refused": "refused",
    "canceled": "refused",
    "cancelled": "refused",
    "5": "expired",
    "expired": "expired",
    "timeout": "expired",
}

_SECOND_VERIFY_QR_SUBTYPES = {
    "qr_code_verify",
    "qr_code_face_verify",
    "face_verify",
    "user_msg_verify",
    "scan_qr",
}

_RISK_FAILURES: dict[str, tuple[str, str]] = {
    "slider_captcha": (
        "抖音触发安全验证码（滑块/点选/旋转风控），网页端无法自动通过。"
        "请改用本地电脑运行「1.本地运行.bat」（输入 1）扫码成功后，在当前页面点击「上传 state.json 文件」导入登录态",
        "slider_captcha",
    ),
    "interactive_sms": (
        "该账号触发手机短信验证码验证，无法在云端网页直接完成。"
        "请改用本地电脑运行「1.本地运行.bat」（输入 1）完成短信验证并登录后，点击「上传 state.json 文件」导入登录态",
        "sms_verify_required",
    ),
    "interactive_password": (
        "该账号触发账号密码二次验证，无法在云端网页自动输入。"
        "请改用本地电脑运行「1.本地运行.bat」（输入 1）完成登录后，点击「上传 state.json 文件」导入登录态",
        "pwd_verify_required",
    ),
    "interactive_email": (
        "该账号触发邮箱验证码验证，无法在云端网页自动完成。"
        "请改用本地电脑运行「1.本地运行.bat」（输入 1）完成登录后，点击「上传 state.json 文件」导入登录态",
        "email_verify_required",
    ),
    "interactive_other": (
        "该账号触发抖音交互式安全验证，网页端无法自动通过。"
        "请改用本地电脑运行「1.本地运行.bat」（输入 1）完成登录后，点击「上传 state.json 文件」导入登录态",
        "second_verify_required",
    ),
    "qr_refused": (
        "你在手机抖音 App 中取消了本次登录确认，请重新发起扫码",
        "qr_refused",
    ),
}

_STATIC_EXTS = (".js", ".css", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif", ".woff", ".woff2", ".ttf", ".mp4")

_slot_seq = itertools.count(1)
_slot_guard = threading.Lock()
_slot_holders: set = set()

_guard = threading.Lock()
_sessions: dict[str, dict] = {}
_stop_flags: dict[str, threading.Event] = {}


class CancelledError(Exception):
    """扫码会话被用户主动取消或硬超时中止。"""


class _SessionExpiredError(Exception):
    """二维码或二次安全验证二维码达到刷新上限过期。"""


class _RiskControlError(Exception):
    """检测到确定无法在云端自动完成的安全验证或用户拒登。"""

    def __init__(self, phase: str, message: str, error_code: str) -> None:
        super().__init__(message)
        self.phase = phase
        self.message = message
        self.error_code = error_code


def _acquire_slot_tracked(token) -> None:
    """获取全局并发名额并按会话 token 登记归属，防止跨会话误释放。"""
    acquire_browser_slot()
    with _slot_guard:
        _slot_holders.add(token)


def _release_slot_once(token) -> None:
    with _slot_guard:
        if token not in _slot_holders:
            return
        _slot_holders.discard(token)
    release_browser_slot()


def _hard_expire(aid: str, target_st: dict | None = None) -> None:
    """硬超时保护：工作线程卡死（如浏览器进程被杀后同步调用挂起）时强制终态。仅针对指定会话实例生效。"""
    with _guard:
        st = _sessions.get(aid)
        if target_st is not None and st is not target_st:
            return  # 该账号已开启新会话，旧超时器不处理
        if st and st["status"] in ("queuing", "starting", "waiting_scan"):
            st.update(status="expired", phase="expired", message="扫码会话超时，请重新发起扫码", qrcode="", deep_link="")
            logger.warning("[%s] 扫码会话触发硬超时保护（工作线程疑似卡死）", aid)
        ref_st = target_st if target_st is not None else st
        flag = ref_st.get("_stop_flag") if isinstance(ref_st, dict) else None
        if flag is None and target_st is None:
            flag = _stop_flags.get(aid)
        slot_token = ref_st.get("_slot_token") if isinstance(ref_st, dict) else None
        if slot_token is None and target_st is None:
            slot_token = aid
    if flag:
        flag.set()
    if slot_token is not None:
        _release_slot_once(slot_token)


def _new_state(aid: str, **fields) -> dict:
    st = {
        "status": "starting",
        "phase": "starting",
        "message": "正在启动扫码环境…",
        "qrcode": "",
        "deep_link": "",
        "scan_device": "",
        "started_at": time.time(),
        "last_active": time.time(),
        "error": "",
    }
    st.update(fields)
    return st


def _public(st: dict) -> dict:
    cur_status = st["status"]
    phase = st.get("phase") or cur_status
    # 已扫码 / 已确认阶段隐藏旧登录二维码，直到登录完成或触发新的二次验证二维码
    show_qr = cur_status == "waiting_scan" and phase not in ("scanned", "confirmed")
    return {
        "status": cur_status,
        "phase": phase,
        "message": st["message"],
        "qrcode": st["qrcode"] if show_qr else "",
        "deep_link": st.get("deep_link", "") if show_qr else "",
        "scan_device": st.get("scan_device", ""),
        "error": st["error"],
    }


def start(account_id: str) -> dict:
    """为指定账号启动扫码会话（幂等：已有活跃会话则直接返回其状态）。"""
    with _guard:
        old = _sessions.get(account_id)
        if old and old["status"] in ("queuing", "starting", "waiting_scan"):
            return {"ok": True, "resumed": True, **_public(old)}
        flag = threading.Event()
        slot_token = (account_id, next(_slot_seq))
        _stop_flags[account_id] = flag
        st = _new_state(
            account_id,
            status="queuing",
            phase="queuing",
            message="正在排队获取浏览器名额…",
            _stop_flag=flag,
            _slot_token=slot_token,
        )
        watchdog = threading.Timer(SESSION_TIMEOUT + 90, lambda: _hard_expire(account_id, st))
        watchdog.daemon = True
        st["_watchdog"] = watchdog
        _sessions[account_id] = st
        snapshot = _public(st)

    t = threading.Thread(target=_session_worker, args=(account_id, flag, st), daemon=True)
    t.start()
    watchdog.start()
    logger.info("[%s] 网页扫码会话已启动", account_id)
    return {"ok": True, "resumed": False, **snapshot}


def status(account_id: str) -> dict:
    """查询会话状态（前端轮询入口）。无会话时返回 idle。"""
    with _guard:
        st = _sessions.get(account_id)
        if not st:
            return {
                "status": "idle",
                "phase": "idle",
                "message": "",
                "qrcode": "",
                "deep_link": "",
                "scan_device": "",
                "error": "",
            }
        if st["status"] == "waiting_scan":
            st["last_active"] = time.time()
        return _public(st)


def cancel(account_id: str) -> dict:
    """取消/终止会话并释放浏览器。"""
    with _guard:
        st = _sessions.get(account_id)
        if st:
            wd = st.get("_watchdog")
            if wd and hasattr(wd, "cancel"):
                try:
                    wd.cancel()
                except Exception:
                    pass
        if not st or st["status"] in ("success", "failed", "expired", "cancelled"):
            _sessions.pop(account_id, None)
            return {"ok": True, "message": "无进行中的扫码会话"}
        flag = st.get("_stop_flag") or _stop_flags.get(account_id)
    if flag:
        flag.set()
    for _ in range(30):
        time.sleep(0.1)
        with _guard:
            cur = _sessions.get(account_id)
            if not cur or cur["status"] not in ("queuing", "starting", "waiting_scan"):
                break
    else:
        with _guard:
            cur = _sessions.get(account_id)
            if cur and cur["status"] in ("waiting_scan",):
                cur["status"] = "cancelled"
                cur["phase"] = "cancelled"
                cur["message"] = "已取消"
    logger.info("[%s] 扫码会话已取消", account_id)
    return {"ok": True, "message": "已取消"}


def _set(aid: str, **fields) -> None:
    with _guard:
        st = _sessions.get(aid)
        if st is None:
            return
        st.update(fields)
        st["last_active"] = time.time()


def _is_stopped(aid: str) -> bool:
    flag = _stop_flags.get(aid)
    return bool(flag and flag.is_set())


def _get_context_cookies(context) -> list[dict]:
    """读取 BrowserContext 全域 Cookie（覆盖 .douyin.com / sso.douyin.com 等所有域）。"""
    try:
        return context.cookies() or []
    except TypeError:
        try:
            return context.cookies("https://www.douyin.com") or []
        except Exception:
            return []
    except Exception:
        return []


def _has_login_cookie(cookies: list[dict]) -> bool:
    """判定 Cookie 列表中是否存在未过期的有效抖音登录凭证。"""
    now = time.time()
    for c in cookies or []:
        if c.get("name") in _LOGIN_COOKIE_NAMES and c.get("value"):
            exp = c.get("expires")
            if exp is not None and 0 < exp <= now:
                continue
            return True
    return False


def _qr_fingerprint(src_or_b64: str) -> str:
    """提取二维码内容的标准化 SHA1 指纹，消除 data URL 前缀差异引起的重复判断。"""
    if not src_or_b64:
        return ""
    body = src_or_b64.split("base64,", 1)[-1].strip()
    return hashlib.sha1(body.encode("utf-8", errors="ignore")).hexdigest()


def _normalize_qr_src(src: str) -> str | None:
    """将 base64 原文、HTTP URL 或 data URL 统一转换为 data URL。"""
    if not src or len(src.strip()) <= 50:
        return None
    s = src.strip()
    if s.startswith("data:image"):
        return s
    if s.startswith("http"):
        try:
            resp = requests.get(s, timeout=8)
            if resp.ok and resp.content:
                b64 = base64.b64encode(resp.content).decode()
                return f"data:image/png;base64,{b64}"
        except Exception:
            return None
        return None
    return f"data:image/png;base64,{s}"


def _qr_looks_valid(img) -> bool:
    """像素级校验二维码图：黑白像素须同时占显著比例。"""
    try:
        g = img.convert("L")
        hist = g.histogram()
        total = sum(hist)
        if not total:
            return False
        dark = sum(hist[:64]) / total
        light = sum(hist[192:]) / total
        return dark > 0.04 and light > 0.04
    except Exception:
        return False


def _enhance_qr_image(data_url: str) -> tuple[str, str, bool]:
    """对提取到的二维码做白边静区补全与短链提取。返回 (data_url, deep_link, valid)。"""
    deep_link = ""
    if not data_url or not data_url.startswith("data:image"):
        return data_url, deep_link, False
    try:
        from io import BytesIO
        from PIL import Image

        raw_b64 = data_url.split("base64,")[1] if "base64," in data_url else data_url
        img_data = base64.b64decode(raw_b64)
        original_rgba = Image.open(BytesIO(img_data)).convert("RGBA")

        bg = Image.new("RGBA", original_rgba.size, (255, 255, 255, 255))
        composited = Image.alpha_composite(bg, original_rgba).convert("RGB")
        valid = _qr_looks_valid(composited)

        pad = 32
        padded_img = Image.new(
            "RGB", (composited.size[0] + pad * 2, composited.size[1] + pad * 2), "WHITE"
        )
        padded_img.paste(composited, (pad, pad))

        try:
            import zxingcpp

            results = zxingcpp.read_barcodes(padded_img)
            if results:
                qr_text = results[0].text
                if _is_allowed_deep_link(qr_text):
                    deep_link = qr_text
        except Exception:
            pass

        buf = BytesIO()
        padded_img.save(buf, format="PNG")
        enhanced_b64 = base64.b64encode(buf.getvalue()).decode()
        return f"data:image/png;base64,{enhanced_b64}", deep_link, valid
    except Exception:
        return data_url, deep_link, True


def _is_allowed_deep_link(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False
    scheme = (parsed.scheme or "").lower()
    if scheme.startswith(("snssdk", "douyin")):
        return True
    if scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in ("douyin.com", "snssdk.com", "iesdouyin.com"))


def _prepare_qr_payload(raw_src: str, fallback_deep_link: str = "") -> tuple[str, str, str, bool]:
    """标准化并增强二维码，返回 (enhanced_data_url, deep_link, raw_fp, valid)。"""
    data_url = _normalize_qr_src(raw_src)
    if not data_url:
        return "", "", "", False
    raw_fp = _qr_fingerprint(data_url)
    enhanced, decoded_dl, valid = _enhance_qr_image(data_url)
    dl = decoded_dl or (fallback_deep_link if _is_allowed_deep_link(fallback_deep_link) else "")
    return enhanced, dl, raw_fp, valid


def _safe_json_obj(val) -> dict | None:
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        s = val.strip()
        if s.startswith("{"):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return None
    return None


def _parse_verify_config(headers: dict | None, payload: dict | None) -> dict | None:
    """从响应头（bdturing-verify / X-Vc-Bdturing-Parameters）或响应 JSON 提取 VerifyCenter 决策。"""
    hdrs = {str(k).lower(): v for k, v in (headers or {}).items()}
    candidates: list[tuple[str, object]] = []
    for hk in ("bdturing-verify", "x-vc-bdturing-parameters"):
        if hdrs.get(hk):
            candidates.append((f"header:{hk}", hdrs[hk]))

    if isinstance(payload, dict):
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        for container, prefix in ((payload, "body"), (data, "data")):
            for bk in ("verify_center_decision_conf", "verify_center_secondary_decision_conf"):
                if container.get(bk):
                    candidates.append((f"{prefix}:{bk}", container[bk]))

    for source, raw in candidates:
        obj = _safe_json_obj(raw)
        if not obj:
            continue
        code_val = obj.get("code")
        try:
            code_int = int(code_val) if code_val is not None and str(code_val).strip() != "" else None
        except Exception:
            code_int = None
        subtype = str(obj.get("subtype") or obj.get("verify_way") or "").strip().lower()
        detail = str(obj.get("detail") or "").strip()
        if code_int in (10000, 20000, 30000, 40000) or subtype:
            return {
                "code": code_int,
                "subtype": subtype,
                "detail": detail,
                "source": source,
                "at": time.time(),
            }
    return None


def _map_verify_subtype_to_risk(subtype: str, code: int | None) -> str | None:
    """将 VerifyCenter code/subtype 映射为不可自动通过的风控 key；扫码/刷脸类型返回 None。"""
    st = (subtype or "").lower()
    if code == 10000 or "captcha" in st:
        return "slider_captcha"
    if any(k in st for k in ("sms", "voice", "mobile")):
        return "interactive_sms"
    if any(k in st for k in ("pwd", "password")):
        return "interactive_password"
    if "email" in st:
        return "interactive_email"
    if st in _SECOND_VERIFY_QR_SUBTYPES or any(k in st for k in ("qr", "face", "scan")):
        return None
    if code in (20000, 30000) and st:
        return "interactive_other"
    return None


class _LoginNetworkTracker:
    """被动监听登录流程关键 HTTP 响应（不在回调内执行 Playwright DOM 操作）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.qr_status = "init"
        self.qr_token = ""
        self.scan_device = ""
        self.scanned_at: float | None = None
        self.confirmed_at: float | None = None
        self.redirect_url = ""
        self.saw_qr_api = False
        self.qr_needs_manual_refresh = False
        self._pending_qr: tuple[str, str, str] | None = None
        self._pending_second_qr: tuple[str, str, str] | None = None
        self.verify_event: dict | None = None
        self.api_error: dict | None = None

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "qr_status": self.qr_status,
                "qr_token": self.qr_token,
                "scan_device": self.scan_device,
                "scanned_at": self.scanned_at,
                "confirmed_at": self.confirmed_at,
                "redirect_url": self.redirect_url,
                "saw_qr_api": self.saw_qr_api,
                "qr_needs_manual_refresh": self.qr_needs_manual_refresh,
                "verify_event": dict(self.verify_event) if self.verify_event else None,
                "api_error": dict(self.api_error) if self.api_error else None,
            }

    def pop_pending_qr(self) -> tuple[str, str, str] | None:
        with self._lock:
            item = self._pending_qr
            self._pending_qr = None
            return item

    def pop_pending_second_qr(self) -> tuple[str, str, str] | None:
        with self._lock:
            item = self._pending_second_qr
            self._pending_second_qr = None
            return item

    def clear_manual_refresh_flag(self) -> None:
        with self._lock:
            self.qr_needs_manual_refresh = False

    def on_response(self, response) -> None:
        try:
            url = response.url or ""
            url_l = url.split("?", 1)[0].lower()
            if url_l.endswith(_STATIC_EXTS):
                return
            headers = {str(k).lower(): v for k, v in (response.headers or {}).items()}
            interesting_url = any(
                k in url.lower()
                for k in ("get_qrcode", "check_qrconnect", "/passport/", "verify", "bdturing", "decision", "secsdk", "safe/")
            )
            has_verify_hdr = "bdturing-verify" in headers or "x-vc-bdturing-parameters" in headers
            if not interesting_url and not has_verify_hdr:
                return
            payload = None
            ctype = str(headers.get("content-type", "")).lower()
            if "json" in ctype or interesting_url:
                try:
                    payload = response.json()
                except Exception:
                    payload = None
            self._ingest_response_data(url, getattr(response, "status", 200), headers, payload)
        except Exception:
            pass

    def _ingest_response_data(
        self, url: str, http_status: int, headers: dict, payload: dict | None
    ) -> None:
        url_l = (url or "").lower()
        now = time.time()
        vconf = _parse_verify_config(headers, payload)

        with self._lock:
            if vconf:
                self.verify_event = vconf

            if not isinstance(payload, dict):
                return

            data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            is_safe_endpoint = "/passport/safe/" in url_l or "second" in url_l or "verify" in url_l

            if "get_qrcode" in url_l:
                qr = str(data.get("qrcode") or payload.get("qrcode") or "").strip()
                dl = str(data.get("qrcode_index_url") or payload.get("qrcode_index_url") or "").strip()
                tok = str(data.get("token") or payload.get("token") or "").strip()
                if len(qr) > 50:
                    if is_safe_endpoint:
                        self._pending_second_qr = (qr, dl, "safe_get_qrcode")
                    else:
                        self.saw_qr_api = True
                        self.qr_status = "new"
                        self.qr_needs_manual_refresh = False
                        if tok:
                            self.qr_token = tok
                        self._pending_qr = (qr, dl, "get_qrcode")
                return

            if "check_qrconnect" in url_l:
                raw_status = str(data.get("status", "")).strip().lower()
                mapped = _QR_STATUS_MAP.get(raw_status)
                qr = str(data.get("qrcode") or "").strip()
                dl = str(data.get("qrcode_index_url") or "").strip()
                tok = str(data.get("token") or "").strip()

                if is_safe_endpoint:
                    if mapped == "expired" and len(qr) > 50:
                        self._pending_second_qr = (qr, dl, "safe_silent_refresh")
                else:
                    self.saw_qr_api = True
                    if mapped == "scanned":
                        self.qr_status = "scanned"
                        self.scanned_at = self.scanned_at or now
                        dev_info = data.get("scan_device_info")
                        if isinstance(dev_info, dict):
                            self.scan_device = str(dev_info.get("device_name") or "").strip()
                        elif data.get("device_name"):
                            self.scan_device = str(data.get("device_name")).strip()
                    elif mapped == "confirmed":
                        self.qr_status = "confirmed"
                        self.confirmed_at = self.confirmed_at or now
                        if data.get("redirect_url"):
                            self.redirect_url = str(data["redirect_url"])
                    elif mapped == "refused":
                        self.qr_status = "refused"
                    elif mapped == "expired":
                        if len(qr) > 50:
                            # 抖音前 5 次过期会在 check_qrconnect 返回新码，前端静默换图但不弹窗
                            self.qr_status = "new"
                            self.qr_needs_manual_refresh = False
                            if tok:
                                self.qr_token = tok
                            self._pending_qr = (qr, dl, "silent_refresh")
                        else:
                            self.qr_status = "expired"
                            self.qr_needs_manual_refresh = True
                    elif mapped == "new" and self.qr_status in ("init", "expired"):
                        self.qr_status = "new"

                err_code = data.get("error_code") or payload.get("error_code")
                if err_code and str(err_code) != "0":
                    desc = str(
                        data.get("description") or payload.get("description") or payload.get("message") or ""
                    ).strip()
                    self.api_error = {"code": err_code, "description": desc, "url": url, "at": now}
                return

            if is_safe_endpoint:
                qr = str(
                    data.get("qrcode") or data.get("qr_code") or payload.get("qrcode") or payload.get("qr_code") or ""
                ).strip()
                dl = str(data.get("qrcode_index_url") or payload.get("qrcode_index_url") or "").strip()
                if len(qr) > 50:
                    self._pending_second_qr = (qr, dl, "safe_payload")


_INSPECT_FRAME_JS = r"""
() => {
    const isVisible = (el) => {
        if (!el) return false;
        const st = window.getComputedStyle(el);
        if (!st || st.display === 'none' || st.visibility === 'hidden' || parseFloat(st.opacity || '1') === 0) {
            return false;
        }
        const r = el.getBoundingClientRect();
        return r.width > 1 && r.height > 1;
    };
    const norm = (el) => ((el && (el.innerText || el.textContent)) || '').replace(/\s+/g, ' ').trim();
    const toDataUrl = (el) => {
        if (!el || !isVisible(el)) return null;
        const r = el.getBoundingClientRect();
        if (r.width < 90 || r.width > 420 || Math.abs(r.width - r.height) > 25) return null;
        if (el.tagName === 'CANVAS') {
            try { return el.toDataURL('image/png'); } catch (e) { return null; }
        }
        const src = el.currentSrc || el.getAttribute('src') || el.src || '';
        if (src.startsWith('data:image') && src.length > 50) return src;
        if (src.startsWith('http')) {
            try {
                const c = document.createElement('canvas');
                c.width = el.naturalWidth || Math.round(r.width);
                c.height = el.naturalHeight || Math.round(r.height);
                if (c.width > 0 && c.height > 0) {
                    c.getContext('2d').drawImage(el, 0, 0, c.width, c.height);
                    return c.toDataURL('image/png');
                }
            } catch (e) {}
            return src;
        }
        return null;
    };

    // 1. 初始登录框二维码 / 过期提示 / 已扫码头像视图
    let loginQrSrc = '';
    const qrEls = document.querySelectorAll(
        '#animate_qrcode_container img, #animate_qrcode_container canvas, ' +
        '[data-e2e="login-qrcode"] img, [data-e2e="login-qrcode"] canvas'
    );
    for (const el of qrEls) {
        const d = toDataUrl(el);
        if (d) { loginQrSrc = d; break; }
    }

    const expEl = document.querySelector('#douyin_login_comp_scan_code_qrcode_expired');
    const loginPanel = document.querySelector('#douyin_login_comp_flat_panel, #animate_qrcode_container');
    const loginPanelText = loginPanel ? norm(loginPanel) : '';
    const loginQrExpired = Boolean(
        (expEl && isVisible(expEl)) ||
        (loginPanel && isVisible(loginPanel) && /二维码已过期|二维码已失效|点击刷新/.test(loginPanelText))
    );

    const avatarEl = document.querySelector('#douyin_login_comp_scan_code_avatar');
    const scannedText = (avatarEl && isVisible(avatarEl)) ? norm(avatarEl).slice(0, 120) : '';

    // 2. 可见验证码检测（严格跳过 0x0 隐藏容器与后台无感 rmc-nocaptcha）
    const captchaSels = [
        '#vc_captcha_wrapper',
        '#captcha_container',
        '#captcha-verify-image',
        '.captcha_verify_container',
        '[class*="captcha_verify"]',
    ];
    let captchaVisible = false;
    let captchaHint = '';
    for (const sel of captchaSels) {
        for (const el of document.querySelectorAll(sel)) {
            if (!isVisible(el)) continue;
            const r = el.getBoundingClientRect();
            if (r.width >= 80 && r.height >= 40) {
                captchaVisible = true;
                captchaHint = norm(el).slice(0, 80) || sel;
                break;
            }
        }
        if (captchaVisible) break;
    }
    if (!captchaVisible) {
        const bodyText = norm(document.body);
        const m = bodyText.match(
            /拖动滑块|拖动下方滑块|向右拖动|滑块填充拼图|完成拼图|请按顺序点击|请点击下图|旋转图片|使图片角度为正|请在下方图中选出/
        );
        if (m) {
            captchaVisible = true;
            captchaHint = m[0];
        }
    }

    // 3. 二次安全验证容器检测
    const strongSecSels = [
        '#account-container-mask',
        '.vc-second-valid-mask',
        '.vc-container-pclayout',
        '[class*="second-valid"]',
        '[class*="identity-verify"]',
    ];
    const genericModalSels = ['[role="dialog"]', '[class*="verify" i]', '[class*="modal" i]'];

    let secVisible = false;
    let secText = '';
    let secQr = '';
    let hasFaceChoice = false;
    let hasRefreshBtn = false;
    let hasDoneBtn = false;
    let interactiveType = '';

    const extractSecFromEl = (el, txt) => {
        secVisible = true;
        secText = txt.slice(0, 400);
        const qrs = el.querySelectorAll('.scan-container img, .qr-container img, img, canvas');
        for (const q of qrs) {
            if (q.closest('#animate_qrcode_container')) continue;
            const d = toDataUrl(q);
            if (d) { secQr = d; break; }
        }
        if (/手机刷脸验证|刷脸验证|扫码验证|抖音App扫码验证/.test(txt)) {
            hasFaceChoice = true;
        }
        if (/二维码已过期|二维码已失效|已失效|点击刷新/.test(txt)) {
            hasRefreshBtn = true;
        }
        if (!/我已完成短信发送/.test(txt) && /我已完成验证|已完成验证|验证成功/.test(txt)) {
            hasDoneBtn = true;
        } else {
            const btns = el.querySelectorAll('button, [role="button"], a, span, div');
            for (const b of btns) {
                if (!isVisible(b)) continue;
                const bt = norm(b);
                if (bt && bt.length <= 16 && /^(我已完成验证|已完成验证|已完成|验证成功)$/.test(bt)) {
                    hasDoneBtn = true;
                    break;
                }
            }
        }
        if (/接收短信验证码|获取验证码|请输入验证码|短信验证码|发送短信验证|我已完成短信发送|语音验证码/.test(txt)) {
            interactiveType = 'sms';
        } else if (/请输入帐号密码|请输入账号密码|密码验证/.test(txt)) {
            interactiveType = 'password';
        } else if (/邮箱验证码|邮箱验证/.test(txt)) {
            interactiveType = 'email';
        }
    };

    const seen = new Set();
    for (const sel of strongSecSels) {
        for (const el of document.querySelectorAll(sel)) {
            if (seen.has(el)) continue;
            seen.add(el);
            if (!isVisible(el)) continue;
            const r = el.getBoundingClientRect();
            const txt = norm(el);
            if (r.width >= 120 && r.height >= 80 && txt) {
                extractSecFromEl(el, txt);
                break;
            }
        }
        if (secVisible) break;
    }

    if (!secVisible) {
        for (const sel of genericModalSels) {
            for (const el of document.querySelectorAll(sel)) {
                if (seen.has(el)) continue;
                seen.add(el);
                if (!isVisible(el)) continue;
                if (el.id === 'douyin_login_comp_flat_panel' || el.querySelector('#animate_qrcode_container')) {
                    continue;
                }
                const r = el.getBoundingClientRect();
                const txt = norm(el);
                if (r.width >= 120 && r.height >= 80 && /安全验证|身份验证|手机刷脸验证|APP扫一扫完成|我已完成验证|接收短信验证码|发送短信验证|我已完成短信发送|请输入帐号密码|请输入账号密码/.test(txt)) {
                    extractSecFromEl(el, txt);
                    break;
                }
            }
            if (secVisible) break;
        }
    }

    if (!secVisible && !document.querySelector('#animate_qrcode_container')) {
        const bodyTxt = norm(document.body);
        if (/安全验证|身份验证|APP扫一扫完成身份验证|我已完成验证|手机刷脸验证|发送短信验证|请输入帐号密码/.test(bodyTxt)) {
            extractSecFromEl(document.body, bodyTxt);
        }
    }

    return {
        loginQrSrc,
        loginQrExpired,
        scannedText,
        captchaVisible,
        captchaHint,
        secVisible,
        secText,
        secQr,
        hasFaceChoice,
        hasRefreshBtn,
        hasDoneBtn,
        interactiveType,
    };
}
"""


def _inspect_frame(frame) -> dict | None:
    try:
        if hasattr(frame, "evaluate"):
            res = frame.evaluate(_INSPECT_FRAME_JS)
            if isinstance(res, dict):
                return res
    except Exception:
        return None
    return None


def _empty_dom_inspection() -> dict:
    return {
        "loginQrSrc": "",
        "loginQrExpired": False,
        "scannedText": "",
        "captchaVisible": False,
        "captchaHint": "",
        "secVisible": False,
        "secText": "",
        "secQr": "",
        "hasFaceChoice": False,
        "hasRefreshBtn": False,
        "hasDoneBtn": False,
        "interactiveType": "",
        "secFrame": None,
    }


def _inspect_all_frames(page) -> dict:
    """单轮扫描主文档及所有可见子 iframe，聚合登录态、二次验证与风控验证码状态。"""
    merged = _empty_dom_inspection()
    main_frame = getattr(page, "main_frame", page)
    main_res = _inspect_frame(main_frame)
    if main_res:
        merged.update(main_res)
        if main_res.get("secVisible"):
            merged["secFrame"] = main_frame

    for frame in getattr(page, "frames", []) or []:
        if frame is main_frame:
            continue
        f_url = (getattr(frame, "url", "") or "").lower()
        if not f_url or f_url == "about:blank":
            continue

        visible = False
        try:
            fe = frame.frame_element()
            if fe and fe.is_visible():
                box = fe.bounding_box()
                visible = bool(box and box.get("width", 0) >= 120 and box.get("height", 0) >= 80)
        except Exception:
            visible = False

        if not visible:
            continue

        if any(k in f_url for k in ("verifycenter/captcha", "/captcha", "secsdk", "bdturing")) and "nocaptcha" not in f_url:
            merged["captchaVisible"] = True
            merged["captchaHint"] = merged["captchaHint"] or f_url[:80]

        sub = _inspect_frame(frame)
        if not sub:
            continue
        if sub.get("captchaVisible"):
            merged["captchaVisible"] = True
            merged["captchaHint"] = merged["captchaHint"] or sub.get("captchaHint", "")
        if not merged["loginQrSrc"] and sub.get("loginQrSrc"):
            merged["loginQrSrc"] = sub["loginQrSrc"]
        if sub.get("loginQrExpired"):
            merged["loginQrExpired"] = True
        if not merged["scannedText"] and sub.get("scannedText"):
            merged["scannedText"] = sub["scannedText"]
        if sub.get("secVisible"):
            merged["secVisible"] = True
            merged["secFrame"] = frame
            merged["secText"] = sub.get("secText") or merged["secText"]
            merged["secQr"] = sub.get("secQr") or merged["secQr"]
            merged["hasFaceChoice"] = merged["hasFaceChoice"] or bool(sub.get("hasFaceChoice"))
            merged["hasRefreshBtn"] = merged["hasRefreshBtn"] or bool(sub.get("hasRefreshBtn"))
            merged["hasDoneBtn"] = merged["hasDoneBtn"] or bool(sub.get("hasDoneBtn"))
            if not merged["interactiveType"] and sub.get("interactiveType"):
                merged["interactiveType"] = sub["interactiveType"]

    return merged


def _js_click_first(frame_or_page, texts: list[str], exact_only: set[str] | None = None) -> bool:
    """对包含指定文本的首个可见元素执行 JS 点击（绕过遮挡，排除短信提示），成功返回 True。"""
    exact_set = exact_only or set()
    for t in texts:
        try:
            loc = frame_or_page.get_by_text(t, exact=(t in exact_set))
            cnt = loc.count()
            for idx in range(min(cnt, 4)):
                cand = loc.nth(idx)
                try:
                    if hasattr(cand, "is_visible") and not cand.is_visible():
                        continue
                    txt = (cand.inner_text() if hasattr(cand, "inner_text") else "") or ""
                    if "短信" in txt:
                        continue
                except Exception:
                    pass
                cand.evaluate("el => el.click()")
                return True
        except Exception:
            continue
    return False


def _click_second_verify_refresh(frame_or_page) -> bool:
    """刷新二次安全验证弹窗内已过期的二维码。"""
    for sel in (
        ".vc-second-valid-mask .refresh-btn",
        "#account-container-mask .refresh-btn",
        ".vc-container-pclayout .refresh-btn",
        ".refresh-btn",
    ):
        try:
            loc = frame_or_page.locator(sel)
            if loc.count() and loc.first.is_visible():
                loc.first.click(timeout=2000)
                return True
        except Exception:
            continue
    return _js_click_first(frame_or_page, ["点击刷新", "刷新二维码"])


def _wait_and_extract_qrcode(page, timeout_ms: int = 45000) -> str | None:
    """等待二维码出现（支持 img 与 canvas）并提取为 data URL；失败时整页截图兜底。"""
    deadline = time.time() + timeout_ms / 1000
    src = ""
    while time.time() < deadline:
        dom = _inspect_all_frames(page)
        if dom.get("loginQrSrc"):
            src = dom["loginQrSrc"]
            break
        for frame in [page, *(f for f in getattr(page, "frames", []) or [] if f is not getattr(page, "main_frame", page))]:
            for sel in _QR_SELECTORS:
                try:
                    loc = frame.locator(sel)
                    if loc.count() and loc.first.is_visible():
                        candidate = loc.first.get_attribute("src") or ""
                        if len(candidate) > 50:
                            src = candidate
                            break
                except Exception:
                    continue
            if src:
                break
        if src:
            break
        page.wait_for_timeout(400)

    if src:
        normalized = _normalize_qr_src(src)
        if normalized:
            return normalized
    for _attempt in range(2):
        try:
            shot = page.screenshot(timeout=8000)
            return "data:image/png;base64," + base64.b64encode(shot).decode()
        except Exception:
            try:
                page.wait_for_timeout(1500)
            except Exception:
                break
    return None


def _extract_valid_qrcode(page, timeout_ms: int = 45000) -> tuple[str, str]:
    """提取二维码并做像素校验；黑屏/空白过渡帧自动点击刷新重试。"""
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        qr = _wait_and_extract_qrcode(page, timeout_ms=12000)
        if qr:
            enhanced, deep_link, valid = _enhance_qr_image(qr)
            if valid:
                return enhanced, deep_link
            logger.warning("二维码像素校验失败（疑似黑屏/空白过渡帧），尝试刷新重试")
        try:
            _click_qr_refresh(page)
        except Exception:
            pass
        page.wait_for_timeout(2500)
    return "", ""


def _slider_captcha_present(page) -> bool:
    """检测抖音风控验证码（滑块/点选/旋转等）是否真正可见于主文档或子 iframe。"""
    dom = _inspect_all_frames(page)
    if dom.get("captchaVisible"):
        return True
    try:
        for t in _SLIDER_TEXTS:
            loc = page.get_by_text(t, exact=False)
            if loc.count() and loc.first.is_visible():
                return True
    except Exception:
        pass
    return False


def _click_qr_refresh(page) -> None:
    """点击二维码区域的刷新按钮重新出码。"""
    candidates = [
        "#douyin_login_comp_scan_code_qrcode_expired",
        "#animate_qrcode_container",
        'div[class*="qrcode"]',
        'div[class*="refresh"]',
    ]
    for sel in candidates:
        try:
            loc = page.locator(sel)
            if loc.count() and loc.first.is_visible():
                loc.first.click(timeout=3000)
                return
        except Exception:
            continue
    try:
        page.reload(wait_until="domcontentloaded")
        page.wait_for_timeout(3000)
    except Exception:
        pass


def _launch_browser(pw):
    """使用纯无头模式启动浏览器，避免 Xvfb 在低配云服务器造成内存与超时问题。"""
    common = dict(
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--disable-extensions",
            "--disable-software-rasterizer",
            "--renderer-process-limit=2",
            "--no-zygote",
            "--mute-audio",
        ],
        ignore_default_args=["--enable-automation"],
    )
    return pw.chromium.launch(headless=True, **common)


def _acquire_initial_qr(
    page,
    aid: str,
    stop_flag: threading.Event,
    tracker: _LoginNetworkTracker,
    timeout_s: float = 35.0,
) -> tuple[str, str, str, str]:
    """高效提取初始登录二维码，兼容网络监听直取、DOM 提取以及启动期即触发的风控快判。

    返回 (enhanced_qr, deep_link, raw_fp, phase)。
    """
    deadline = time.time() + timeout_s
    tab_clicked = False
    captcha_hits = 0
    interactive_hits = 0
    face_clicked = False
    first_net_qr: tuple[str, str, float] | None = None

    while time.time() < deadline:
        if stop_flag.is_set() or _is_stopped(aid):
            raise CancelledError()

        pending = tracker.pop_pending_qr()
        if pending:
            raw_qr, dl, _src = pending
            first_net_qr = (raw_qr, dl, time.time())

        dom = _inspect_all_frames(page)

        # 优先使用 DOM 中实际挂载出来的二维码，确保前端 React check_qrconnect 轮询已启动
        if dom.get("loginQrSrc"):
            enh, dl, fp, valid = _prepare_qr_payload(dom["loginQrSrc"], first_net_qr[1] if first_net_qr else "")
            if valid:
                return enh, dl, fp, "qr_ready"

        # 若网络 get_qrcode 已拿码且等待超过 1.2s DOM 仍未渲染，也立即返回（React 通常早已就绪）
        if first_net_qr and time.time() - first_net_qr[2] >= 1.2:
            enh, dl, fp, valid = _prepare_qr_payload(first_net_qr[0], first_net_qr[1])
            if valid:
                return enh, dl, fp, "qr_ready"

        if dom.get("secVisible"):
            if dom.get("secQr"):
                enh, dl, fp, valid = _prepare_qr_payload(dom["secQr"])
                if valid:
                    return enh, dl, fp, "second_verify_qr"
            if dom.get("hasFaceChoice") and not face_clicked and dom.get("secFrame"):
                _js_click_first(dom["secFrame"], ["手机刷脸验证", "刷脸验证", "扫码验证"])
                face_clicked = True
                page.wait_for_timeout(800)
                continue
            if dom.get("interactiveType") and (not dom.get("hasFaceChoice") or face_clicked):
                interactive_hits += 1
                if interactive_hits >= 3:
                    key = f"interactive_{dom['interactiveType']}"
                    raise _RiskControlError(key, *_RISK_FAILURES.get(key, _RISK_FAILURES["interactive_other"]))
            else:
                interactive_hits = 0

        if dom.get("captchaVisible"):
            captcha_hits += 1
            if captcha_hits >= 3:
                raise _RiskControlError("slider_captcha", *_RISK_FAILURES["slider_captcha"])
        else:
            captcha_hits = 0

        elapsed = timeout_s - (deadline - time.time())
        if not tab_clicked and elapsed >= 4.0 and not tracker.saw_qr_api:
            tab_clicked = True
            _try_activate_qr_tab(page)

        page.wait_for_timeout(400)

    # 兜底尝试传统选择器提取（无截图误判干扰后仅作最后尝试）
    enh, dl = _extract_valid_qrcode(page, timeout_ms=12000)
    if enh:
        return enh, dl, _qr_fingerprint(enh), "qr_ready"
    if _slider_captcha_present(page):
        raise _RiskControlError("slider_captcha", *_RISK_FAILURES["slider_captcha"])
    raise RuntimeError("未能从页面提取到有效的登录二维码（多次刷新仍为黑屏/空白），请稍后重试")


def _try_activate_qr_tab(page) -> None:
    for action in (
        lambda: page.locator(
            "#douyin_login_comp_flat_panel > div > div:nth-child(2) > div > div:nth-child(4) > p"
        ).click(timeout=500),
        lambda: page.get_by_text("扫码登录").first.click(timeout=500),
        lambda: page.locator("#animate_qrcode_container").first.click(timeout=1000),
    ):
        try:
            action()
        except Exception:
            pass


def _sync_network_qr_updates(
    aid: str,
    tracker: _LoginNetworkTracker,
    snap: dict,
    state: dict,
) -> None:
    """消费网络监听捕捉到的二次验证新码、静默换码以及扫码/确认/拒登状态变更。"""
    net_status = snap["qr_status"]
    if net_status == "refused":
        raise _RiskControlError("qr_refused", *_RISK_FAILURES["qr_refused"])

    pending_sec = tracker.pop_pending_second_qr()
    if pending_sec:
        raw_qr, dl, src = pending_sec
        enh, fin_dl, raw_fp, valid = _prepare_qr_payload(raw_qr, dl)
        if valid and raw_fp != state["last_second_fp"]:
            state["last_second_fp"] = raw_fp
            state["phase"] = "second_verify_qr"
            _set(
                aid,
                status="waiting_scan",
                phase="second_verify_qr",
                qrcode=enh,
                deep_link=fin_dl,
                message="触发安全验证：请使用手机抖音 App 扫描下方新二维码完成验证",
            )
            logger.info("[%s] 监听到二次安全验证二维码（来源：%s），已推送至前端", aid, src)

    pending_qr = tracker.pop_pending_qr()
    if pending_qr and state["phase"] != "second_verify_qr" and net_status not in ("scanned", "confirmed"):
        raw_qr, dl, src = pending_qr
        enh, fin_dl, raw_fp, valid = _prepare_qr_payload(raw_qr, dl)
        if valid and raw_fp != state["last_login_fp"]:
            state["last_login_fp"] = raw_fp
            state["last_login_enh_fp"] = _qr_fingerprint(enh)
            state["silent_refreshes"] += 1
            state["phase"] = "qr_refreshed"
            _set(
                aid,
                status="waiting_scan",
                phase="qr_refreshed",
                qrcode=enh,
                deep_link=fin_dl,
                message=f"二维码已自动刷新（第 {state['silent_refreshes']} 次），请扫描最新二维码",
            )
            logger.info("[%s] 抖音静默更新二维码（来源：%s，第 %d 次），已同步前端", aid, src, state["silent_refreshes"])

    if state["phase"] != "second_verify_qr":
        if net_status == "scanned" and state["phase"] not in ("scanned", "confirmed"):
            state["phase"] = "scanned"
            dev = snap.get("scan_device") or ""
            dev_hint = f"「{dev}」" if dev else ""
            _set(
                aid,
                status="waiting_scan",
                phase="scanned",
                qrcode="",
                deep_link="",
                scan_device=dev,
                message=f"已在手机端扫码，请在{dev_hint}抖音 App 中点击「确认登录」",
            )
            logger.info("[%s] 手机已扫码，等待 App 端确认（设备：%s）", aid, dev or "未知")
        elif net_status == "confirmed" and state["phase"] != "confirmed":
            state["phase"] = "confirmed"
            _set(
                aid,
                status="waiting_scan",
                phase="confirmed",
                qrcode="",
                deep_link="",
                message="手机已确认登录，正在校验安全状态与同步登录凭证…",
            )
            logger.info("[%s] 手机已确认登录，等待下发 Cookie 或二次验证", aid)


def _handle_secondary_verification(
    aid: str,
    page,
    dom: dict,
    snap: dict,
    state: dict,
) -> bool:
    """处理二次安全验证与风控拦截。若需跳过本轮后续常规刷新处理则返回 True。"""
    v_ev = snap.get("verify_event")
    recent_verify = bool(v_ev and (time.time() - v_ev.get("at", 0) < 20))
    sec_frame = dom.get("secFrame") or page

    captcha_active = bool(dom.get("captchaVisible")) or bool(
        recent_verify and v_ev and v_ev.get("code") == 10000 and state["phase"] in ("scanned", "confirmed", "second_verify_qr")
    )
    if captcha_active:
        state["captcha_hits"] += 1
        if state["captcha_hits"] >= 2:
            logger.warning("[%s] 检测到验证码风控拦截（%s）", aid, dom.get("captchaHint") or "VerifyCenter 10000")
            raise _RiskControlError("slider_captcha", *_RISK_FAILURES["slider_captcha"])
        return True
    state["captcha_hits"] = 0

    sec_active = bool(dom.get("secVisible")) or bool(
        recent_verify and v_ev and v_ev.get("code") in (20000, 30000, 40000)
    )
    if not sec_active:
        state["interactive_hits"] = 0
        return False

    if dom.get("hasFaceChoice") and not state["face_choice_clicked"] and not dom.get("secQr"):
        if _js_click_first(sec_frame, ["手机刷脸验证", "刷脸验证", "扫码验证", "抖音App扫码验证"]):
            state["face_choice_clicked"] = True
            state["interactive_hits"] = 0
            logger.info("[%s] 触发安全验证，已自动选择刷脸/扫码验证方式", aid)
            return True

    if dom.get("hasRefreshBtn"):
        if state["second_refreshes"] >= QR_REFRESH_LIMIT:
            raise _SessionExpiredError("安全验证二维码多次过期，请重新发起扫码")
        if _click_second_verify_refresh(sec_frame):
            state["second_refreshes"] += 1
            logger.info("[%s] 二次验证二维码过期，已点击刷新（第 %d 次）", aid, state["second_refreshes"])
            return True

    if dom.get("secQr"):
        enh, fin_dl, raw_fp, valid = _prepare_qr_payload(dom["secQr"])
        if valid and raw_fp != state["last_second_fp"]:
            state["last_second_fp"] = raw_fp
            state["phase"] = "second_verify_qr"
            state["interactive_hits"] = 0
            _set(
                aid,
                status="waiting_scan",
                phase="second_verify_qr",
                qrcode=enh,
                deep_link=fin_dl,
                message="触发安全验证：请使用手机抖音 App 扫描下方新二维码完成验证",
            )
            logger.info("[%s] 已提取二次安全验证页面二维码并推送至前端", aid)

    if state["phase"] == "second_verify_qr" and dom.get("hasDoneBtn"):
        if time.time() - state["last_done_click_at"] >= 2.5:
            if _js_click_first(
                sec_frame,
                ["我已完成验证", "已完成验证", "验证成功", "已完成"],
                exact_only={"已完成"},
            ):
                state["last_done_click_at"] = time.time()
                logger.debug("[%s] 已点击二次验证「我已完成验证」按钮", aid)

    # 非扫码类交互式风控（短信/上行短信/账号密码/邮箱），确认无可用扫码入口后快速报错引导上传
    can_check_block = (not dom.get("hasFaceChoice")) or state["face_choice_clicked"]
    if not dom.get("secQr") and can_check_block and state["phase"] != "second_verify_qr":
        block_key = None
        if dom.get("interactiveType"):
            block_key = f"interactive_{dom['interactiveType']}"
        elif recent_verify and v_ev:
            block_key = _map_verify_subtype_to_risk(v_ev.get("subtype", ""), v_ev.get("code"))
        if block_key:
            state["interactive_hits"] += 1
            if state["interactive_hits"] >= 3:
                logger.warning("[%s] 触发无法自动完成的二次验证类型：%s", aid, block_key)
                raise _RiskControlError(block_key, *_RISK_FAILURES.get(block_key, _RISK_FAILURES["interactive_other"]))
            return True
    state["interactive_hits"] = 0
    return bool(dom.get("secVisible"))


def _poll_until_login(
    aid: str,
    context,
    page,
    tracker: _LoginNetworkTracker,
    stop_flag: threading.Event,
    initial_qr_fp: str,
    initial_qr: str,
    initial_phase: str = "qr_ready",
) -> None:
    """主等待循环：实时同步 Cookie、网络事件、DOM 换码、二次验证及风控拦截。"""
    deadline = time.time() + SESSION_TIMEOUT
    state = {
        "phase": initial_phase,
        "last_login_fp": initial_qr_fp,
        "last_login_enh_fp": _qr_fingerprint(initial_qr),
        "last_second_fp": initial_qr_fp if initial_phase == "second_verify_qr" else "",
        "silent_refreshes": 0,
        "manual_refreshes": 0,
        "second_refreshes": 0,
        "face_choice_clicked": False,
        "last_done_click_at": 0.0,
        "captcha_hits": 0,
        "interactive_hits": 0,
    }
    polls = 0
    confirmed_warned = False

    while time.time() < deadline:
        if stop_flag.is_set() or _is_stopped(aid):
            raise CancelledError()

        cookies = _get_context_cookies(context)
        if _has_login_cookie(cookies):
            _save_state(context, aid)
            _set(
                aid,
                status="success",
                phase="success",
                message=f"登录成功！已保存该账号的登录态（{len(cookies)} 条 Cookie）",
                qrcode="",
                deep_link="",
                error="",
            )
            logger.info("[%s] 网页扫码登录成功，state.json 已更新（%d 条 Cookie）", aid, len(cookies))
            return

        snap = tracker.snapshot()
        _sync_network_qr_updates(aid, tracker, snap, state)

        polls += 1
        if polls % 15 == 0:
            names = ",".join(sorted({c.get("name", "") for c in cookies if c.get("name")}))
            logger.info(
                "[%s] 扫码等待中（phase=%s, net=%s, url=%s, cookies=%s）",
                aid,
                state["phase"],
                snap["qr_status"],
                getattr(page, "url", "")[:80],
                names or "无",
            )

        dom = _inspect_all_frames(page)

        # DOM 兜底检测“手机已扫码待确认”头像面板
        if dom.get("scannedText") and state["phase"] in ("qr_ready", "qr_refreshed"):
            state["phase"] = "scanned"
            _set(
                aid,
                status="waiting_scan",
                phase="scanned",
                qrcode="",
                deep_link="",
                message="已在手机端扫码，请在抖音 App 中点击「确认登录」",
            )

        skip_qr_sync = _handle_secondary_verification(aid, page, dom, snap, state)

        # 仅在非二次验证、且网络未处于已扫码/已确认态时同步过期刷新与静默换码
        if not skip_qr_sync and state["phase"] != "second_verify_qr" and snap["qr_status"] not in ("scanned", "confirmed"):
            if dom.get("loginQrExpired") or snap["qr_needs_manual_refresh"]:
                tracker.clear_manual_refresh_flag()
                state["manual_refreshes"] += 1
                if state["manual_refreshes"] >= QR_REFRESH_LIMIT:
                    _set(aid, status="expired", phase="expired", message="二维码多次过期，请重新发起扫码", qrcode="", deep_link="")
                    return
                _click_qr_refresh(page)
                new_qr, new_dl = _extract_valid_qrcode(page, timeout_ms=20000)
                if new_qr:
                    raw_after = _inspect_all_frames(page).get("loginQrSrc", "")
                    state["last_login_fp"] = _qr_fingerprint(raw_after) or _qr_fingerprint(new_qr)
                    state["last_login_enh_fp"] = _qr_fingerprint(new_qr)
                    tracker.pop_pending_qr()  # 丢弃点击刷新顺带入队的同批 get_qrcode，防重复计数
                    state["phase"] = "qr_refreshed"
                    _set(
                        aid,
                        status="waiting_scan",
                        phase="qr_refreshed",
                        qrcode=new_qr,
                        deep_link=new_dl,
                        message=f"二维码已刷新（第 {state['manual_refreshes']} 次），请重新扫码",
                    )
            elif dom.get("loginQrSrc"):
                raw_dom_fp = _qr_fingerprint(dom["loginQrSrc"])
                if raw_dom_fp != state["last_login_fp"]:
                    enh, fin_dl, _, valid = _prepare_qr_payload(dom["loginQrSrc"])
                    enh_fp = _qr_fingerprint(enh)
                    if valid and enh_fp != state["last_login_enh_fp"]:
                        state["last_login_fp"] = raw_dom_fp
                        state["last_login_enh_fp"] = enh_fp
                        state["silent_refreshes"] += 1
                        state["phase"] = "qr_refreshed"
                        _set(
                            aid,
                            status="waiting_scan",
                            phase="qr_refreshed",
                            qrcode=enh,
                            deep_link=fin_dl,
                            message=f"二维码已自动更新（第 {state['silent_refreshes']} 次），请扫描最新二维码",
                        )
                        logger.info("[%s] 检测到页面二维码图静默变更（第 %d 次），已同步推送", aid, state["silent_refreshes"])

        # 确认登录后长时间卡住的诊断与错误透出
        if state["phase"] == "confirmed" and snap.get("confirmed_at"):
            stalled_s = time.time() - snap["confirmed_at"]
            if stalled_s > 20 and not confirmed_warned:
                confirmed_warned = True
                logger.warning(
                    "[%s] 手机已确认 %.1fs 仍未获得登录 Cookie（url=%s, api_err=%s, verify=%s）",
                    aid,
                    stalled_s,
                    getattr(page, "url", ""),
                    snap.get("api_error"),
                    snap.get("verify_event"),
                )
            if stalled_s > 45 and snap.get("api_error"):
                err = snap["api_error"]
                desc = err.get("description") or f"错误码 {err.get('code')}"
                raise _RiskControlError(
                    "confirmed_api_error",
                    f"手机确认后抖音返回风控或异常（{desc}），请改用本地电脑扫码后上传 state.json",
                    f"douyin_error_{err.get('code')}",
                )

        page.wait_for_timeout(1000)

    expired_msg = (
        "手机已确认登录，但凭证同步超时（可能被风控静默拦截），请重试或改用本地上传 state.json"
        if state["phase"] == "confirmed"
        else "扫码超时，请重新发起扫码"
    )
    _set(aid, status="expired", phase="expired", message=expired_msg, qrcode="", deep_link="")
    logger.info("[%s] 扫码会话超时结束（phase=%s）", aid, state["phase"])


def _chrome_major_version(browser) -> str:
    try:
        v = browser.version
        if v and "." in v:
            return v.split(".")[0]
    except Exception:
        pass
    return "124"


def _session_worker(aid: str, stop_flag: threading.Event, st: dict | None = None) -> None:
    pw = None
    browser = None
    slot_token = st.get("_slot_token") if isinstance(st, dict) and "_slot_token" in st else aid
    try:
        _acquire_slot_tracked(slot_token)
        if stop_flag.is_set() or _is_stopped(aid):
            raise CancelledError()

        if sync_playwright is None:
            raise RuntimeError("系统未安装 playwright 依赖，请在服务器执行: pip install playwright && playwright install chromium")

        # 扫码前先经 executor 安全回收空闲池化浏览器，防止低配 ECS 内存双开耗尽
        try:
            from .browser import reclaim_idle_from_executor

            reclaimed = reclaim_idle_from_executor(force=True, timeout=2.5)
            if reclaimed:
                logger.info("[%s] 扫码前已清理 %d 个空闲浏览器实例，释放内存", aid, reclaimed)
        except Exception:
            pass

        _set(aid, status="starting", phase="starting", message="正在启动无头浏览器…")
        pw = sync_playwright().start()
        browser = _launch_browser(pw)

        chrome_major = _chrome_major_version(browser)
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                f"(KHTML, like Gecko) Chrome/{chrome_major}.0.0.0 Safari/537.36"
            ),
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
            ignore_https_errors=True,
        )
        context.add_init_script(
            "const _spoof=(proto)=>{const g=proto.getParameter;"
            "proto.getParameter=function(p){if(p===37445)return 'Intel Inc.';"
            "if(p===37446)return 'Intel Iris OpenGL Engine';return g.apply(this,[p]);};};"
            "if(window.WebGLRenderingContext)_spoof(WebGLRenderingContext.prototype);"
            "if(window.WebGL2RenderingContext)_spoof(WebGL2RenderingContext.prototype);"
        )
        page = context.new_page()
        try:
            from .browser import _apply_stealth

            _apply_stealth(page)
        except Exception:
            pass

        tracker = _LoginNetworkTracker()
        page.on("response", tracker.on_response)

        _set(aid, status="starting", phase="starting", message="正在打开抖音登录页并获取二维码…")
        for _goto_attempt in range(2):
            try:
                page.goto(CHAT_URL, timeout=60000, wait_until="domcontentloaded")
                break
            except Exception:
                if _goto_attempt == 0:
                    page.wait_for_timeout(1500)
                    continue
                logger.info("[%s] 打开登录页超时，继续尝试等待二维码", aid)

        if _is_stopped(aid):
            raise CancelledError()

        enhanced_qr, deep_link, raw_fp, init_phase = _acquire_initial_qr(page, aid, stop_flag, tracker)
        init_msg = (
            "触发安全验证：请使用手机抖音 App 扫描下方二维码完成验证"
            if init_phase == "second_verify_qr"
            else "请使用抖音 App 扫码登录"
        )
        _set(
            aid,
            status="waiting_scan",
            phase=init_phase,
            message=init_msg,
            qrcode=enhanced_qr,
            deep_link=deep_link,
        )

        _poll_until_login(
            aid,
            context,
            page,
            tracker,
            stop_flag,
            initial_qr_fp=raw_fp,
            initial_qr=enhanced_qr,
            initial_phase=init_phase,
        )

    except CancelledError:
        _set(aid, status="cancelled", phase="cancelled", message="已取消", qrcode="", deep_link="")
    except _SessionExpiredError as e:
        _set(aid, status="expired", phase="expired", message=str(e), qrcode="", deep_link="")
        logger.info("[%s] 扫码会话过期终止：%s", aid, e)
    except _RiskControlError as e:
        _set(aid, status="failed", phase=e.phase, message=e.message, error=e.error_code, qrcode="", deep_link="")
        logger.warning("[%s] 扫码会话风控终止（%s）：%s", aid, e.error_code, e.message)
    except Exception as e:
        msg = str(e)[:200]
        _set(aid, status="failed", phase="failed", message=msg or "扫码会话异常", error=msg, qrcode="", deep_link="")
        logger.warning("[%s] 扫码会话异常：%s", aid, msg)
    finally:
        if st is not None:
            wd = st.get("_watchdog")
            if wd and hasattr(wd, "cancel"):
                try:
                    wd.cancel()
                except Exception:
                    pass
        if browser:
            try:
                browser.close()
            except Exception:
                pass
        if pw:
            try:
                pw.stop()
            except Exception:
                pass
        _release_slot_once(slot_token)
        with _guard:
            if _stop_flags.get(aid) is stop_flag:
                _stop_flags.pop(aid, None)

        def _gc_session(target_st):
            with _guard:
                if target_st is not None and _sessions.get(aid) is target_st:
                    _sessions.pop(aid, None)
                    logger.debug("[%s] 历史扫码会话已安全 GC 清理", aid)

        threading.Timer(120, lambda: _gc_session(st)).start()


def _save_state(context, account_id: str) -> None:
    """导出 storage_state 覆盖该账号 state.json（default 账号同步根目录副本）。"""
    state = context.storage_state()
    raw = _ensure_origins(state)
    path: Path = account_state_path(account_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    tmp_path.replace(path)
    if account_id == DEFAULT_ACCOUNT_ID:
        try:
            root_tmp = ROOT_STATE_PATH.with_suffix(".tmp")
            root_tmp.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
            root_tmp.replace(ROOT_STATE_PATH)
        except Exception:
            pass


def _ensure_origins(state) -> dict:
    """storage_state 兼容处理：确保结构与上传校验一致（cookies 列表 + origins）。"""
    if isinstance(state, dict):
        state.setdefault("cookies", [])
        state.setdefault("origins", [])
        return state
    return {"cookies": [], "origins": []}

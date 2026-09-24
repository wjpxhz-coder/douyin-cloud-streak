"""验证台账最新列表同步与去重机制（离线纯逻辑测试，无需浏览器和网络）。

覆盖用户诉求：
1. 每次刷新联系人，严格呈现最新好友列表
2. 彻底去除重复（消除 NBSP、全角空格、零宽字符、PUA 字体图标带来的假重复）
3. 自动剔除已不在最新列表中的历史旧联系人
4. 安全继承已勾选、自定义文案、发送历史等用户配置
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import ledger
from core.ledger import norm_name, merge_consumer_contacts, load_ledger, set_selected, set_streak

PASS = 0
FAIL = 0


def check(name: str, cond: bool) -> None:
    global PASS, FAIL
    if cond:
        print(f"PASS: {name}")
        PASS += 1
    else:
        print(f"FAIL: {name}")
        FAIL += 1


# ── 环境隔离：写入独立临时目录 ───────────────────────────
tmp_dir = Path(tempfile.mkdtemp(prefix="ledger_sync_test_"))
orig_account_dir = ledger.account_dir
ledger.account_dir = lambda account_id=None: tmp_dir

try:
    # ── 1. norm_name 归一化清洗 ──────────────────────────────
    check("T1 NBSP 替换为空格", norm_name("舞阳趣玩\xa0Switch") == "舞阳趣玩 Switch")
    check("T2 PUA 字体图标剔除", norm_name("甲先生有逻辑 \U000f0807") == "甲先生有逻辑")
    check("T3 零宽字符剔除", norm_name("测试\u200b好友\ufeff") == "测试好友")
    check("T4 全角空格替换", norm_name("你好\u3000世界") == "你好 世界")
    check("T5 连续空格合并与两端去除", norm_name("  小   明   ") == "小 明")

    # ── 2. load_ledger 自动合并旧数据中的重复条目 ────────────
    dirty_data = [
        {"display_name": "甲先生有逻辑 \U000f0807", "streak_days": 10, "selected": True, "avatar": "av1"},
        {"display_name": "甲先生有逻辑", "streak_days": 15, "selected": False, "avatar": ""},
        {"display_name": "舞阳趣玩\xa0Switch", "streak_days": 0, "selected": True},
        {"display_name": "舞阳趣玩 Switch", "streak_days": 5, "selected": False, "avatar": "av2"},
        {"display_name": "旧好友A", "streak_days": 0, "selected": True, "channel": "consumer"},
    ]
    ledger._save(dirty_data)
    loaded = load_ledger()
    loaded_map = {e["display_name"]: e for e in loaded}
    check("T6 脏数据自动去重（5条合并为3条）", len(loaded) == 3)
    check("T7 甲先生去重并保留更高火花与勾选",
          loaded_map["甲先生有逻辑"]["streak_days"] == 15 and
          loaded_map["甲先生有逻辑"]["selected"] is True and
          loaded_map["甲先生有逻辑"]["avatar"] == "av1")
    check("T8 舞阳趣玩去重并保留有效头像与勾选",
          loaded_map["舞阳趣玩 Switch"]["selected"] is True and
          loaded_map["舞阳趣玩 Switch"]["avatar"] == "av2" and
          loaded_map["舞阳趣玩 Switch"]["streak_days"] == 5)

    # ── 3. merge_consumer_contacts 刷新为最新列表并清理旧联系人 ─
    new_contacts = [
        {"name": "甲先生有逻辑", "streak": 20, "avatar": "av_new"},
        {"name": "小新", "streak": "🔥 3天", "avatar": "av_xin"},
    ]
    stats = merge_consumer_contacts(new_contacts)
    cur_ledger = load_ledger()
    cur_map = {e["display_name"]: e for e in cur_ledger}

    check("T9 台账总数仅为最新获取的2人", stats["total"] == 2 and len(cur_ledger) == 2)
    check("T10 统计返回：新增1人、更新1人、清理旧人2人",
          stats["added"] == 1 and stats["updated"] == 1 and stats["removed"] == 2)
    check("T11 旧好友A已不在最新台账中", "旧好友A" not in cur_map)
    check("T12 甲先生保留原有 selected=True 配置", cur_map["甲先生有逻辑"]["selected"] is True)
    check("T13 甲先生火花更新为最新的20天", cur_map["甲先生有逻辑"]["streak_days"] == 20)
    check("T14 新好友小新成功入库且火花解析为3天",
          "小新" in cur_map and cur_map["小新"]["streak_days"] == 3)

    # ── 4. 空列表安全防护：同步失败或为空时绝不清空台账 ──────
    empty_stats = merge_consumer_contacts([])
    after_empty = load_ledger()
    check("T15 空列表安全兜底：未清空台账", len(after_empty) == 2 and empty_stats["total"] == 2)

    # ── 5. set_selected 规范化匹配 ─────────────────────────
    set_selected([{"display_name": "小新 \U000f0807", "selected": True, "custom_message": "你好小新"}])
    reloaded = load_ledger()
    reloaded_map = {e["display_name"]: e for e in reloaded}
    check("T16 set_selected 带特殊符号仍能精确匹配并更新勾选与专属文案",
          reloaded_map["小新"]["selected"] is True and
          reloaded_map["小新"]["custom_message"] == "你好小新" and
          len(reloaded) == 2)

    # ── 6. set_streak 规范化匹配 ───────────────────────────
    ok = set_streak("小新\xa0", 99)
    after_streak = load_ledger()
    check("T17 set_streak 带NBSP仍能精确命中更新",
          ok is True and {e["display_name"]: e for e in after_streak}["小新"]["streak_days"] == 99)

finally:
    ledger.account_dir = orig_account_dir

print(f"\n测试汇总: {PASS} passed, {FAIL} failed")
if FAIL > 0:
    sys.exit(1)

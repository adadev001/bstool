import os
import json
import requests
import yaml
import feedparser
import logging
import time
import random
from google import genai
from atproto import Client, models
from datetime import datetime, timedelta, timezone

# ==========================
# 定数
# ==========================

SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"
MAX_POST_LENGTH = 140


# =============================================
# NVD 設計まとめ（設計意図）
#
# - NVD は総件数が 30万件以上あるため
#   max_items だけでは古い CVE が混ざる
#
# - 公開日での期間指定を導入
#   state に last_checked_at を 1項目だけ追加
#
# - 初回実行でも「直近1日」に限定し暴走しない
# - max_items / skip_existing / YAML 設計を壊さない
# =============================================


# ==========================
# 共通ユーティリティ
# ==========================

def utc_now():
    """UTC現在時刻を取得（NVDはUTC前提）"""
    return datetime.now(timezone.utc)


def isoformat(dt):
    """NVD API 用 ISO8601（ミリ秒＋Z）"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ==========================
# state / config
# ==========================

def load_config():
    with open(SITES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


# ==========================
# NVD API
# ==========================

def fetch_nvd(site, pub_start, pub_end):
    """
    NVD (CVE) 取得

    - 期間指定は必須
    - 初回 / 2回目の判定は呼び出し側で行う
    """

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    max_items = site.get("max_items", 50)

    params = {
        "resultsPerPage": max_items,
        "pubStartDate": isoformat(pub_start),
        "pubEndDate": isoformat(pub_end),
    }

    logging.info(
        f"NVD query: {params['pubStartDate']} → {params['pubEndDate']}"
    )

    resp = requests.get(base_url, params=params, timeout=30)
    resp.raise_for_status()

    data = resp.json()
    vulns = data.get("vulnerabilities", [])

    items = []
    for v in vulns:
        items.append(v.get("cve", {}))

    return items


# ==========================
# RSS
# ==========================

def fetch_rss(site, state_for_site):
    feed = feedparser.parse(site["url"])
    items = []

    max_items = site.get("max_items", 1)

    for entry in feed.entries[:max_items]:
        link = entry.get("link")
        if not link:
            continue

        items.append({
            "id": link,
            "text": f"{entry.get('title', '')}\n{entry.get('summary', '')}",
            "url": link
        })

    return items


# ==========================
# メイン処理
# ==========================

def main():

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s:%(message)s"
    )

    # --------------------------
    # 初期化
    # --------------------------

    config = load_config()
    sites = config.get("sites", {})
    settings = config.get("settings", {})

    state = load_state()

    now = utc_now()

    # --------------------------
    # NVD 期間決定（ここが唯一の場所）
    # --------------------------

    if "last_checked_at" not in state:
        # 初回実行：直近1日のみ
        logging.info("Initial NVD run → last 1 day")
        pub_start = now - timedelta(days=1)
    else:
        pub_start = datetime.fromisoformat(
            state["last_checked_at"].replace("Z", "+00:00")
        )

    pub_end = now

    # --------------------------
    # サイト処理
    # --------------------------

    for site_key, site in sites.items():

        if not site.get("enabled", True):
            continue

        # site 用 state 初期化
        state.setdefault(site_key, [])

        logging.info(f"Processing: {site_key}")

        if site["type"] == "rss":
            items = fetch_rss(site, state[site_key])

        elif site_key == "nvd":
            items = fetch_nvd(site, pub_start, pub_end)

        else:
            logging.warning(f"Unknown type: {site['type']}")
            continue

        for item in items:
            if item.get("id") in state[site_key]:
                continue

            # --- 実処理（投稿など） ---
            logging.info(f"New item: {item.get('id')}")

            state[site_key].append(item.get("id"))

    # ---------------------------------------------
    # state 更新（事故防止）
    #
    # 全サイトの処理が「正常終了」したあとにのみ実行
    #
    # ここで更新しないと:
    # - 次回実行時に古い期間を再取得してしまう
    #
    # 途中で例外が出た場合に更新すると:
    # - 取りこぼしが発生する
    # ---------------------------------------------

    state["last_checked_at"] = isoformat(now)
    save_state(state)


if __name__ == "__main__":
    main()

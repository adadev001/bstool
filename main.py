import os
import json
import requests
import yaml
import feedparser
import logging
import time
import random
from google import genai
from atproto import Client
from datetime import datetime, timedelta, timezone

# =========================================================
# 定数定義
# =========================================================
SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"

MAX_POST_LENGTH = 140
SUMMARY_HARD_LIMIT = 80

# entries の保持ポリシー
ENTRY_RETENTION_DAYS = 2   # 何日分保持するか
ENTRY_MAX = 6              # 最大件数（通常 max_items=3 の2倍）

# =========================================================
# 時刻ユーティリティ
# =========================================================
def utc_now():
    """UTC の現在時刻を返す"""
    return datetime.now(timezone.utc)

def isoformat(dt):
    """datetime → ISO8601 (Z付き)"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_iso(ts):
    """ISO8601 → datetime"""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

# =========================================================
# State 管理
# =========================================================
def load_state():
    """
    State v2 をロード。
    ファイルが存在しない場合は初期構造を返す。
    """
    if not os.path.exists(STATE_FILE):
        return {
            "version": 2,
            "updated_at": isoformat(utc_now()),

            # NVD で投稿済みの CVE 一覧
            # → JVN が同じ CVE を検知したらスキップするための集合
            "known_cves": {},

            # サイト別 State
            "sites": {}
        }

    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_state(state):
    """State を JSON として保存"""
    state["updated_at"] = isoformat(utc_now())
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

def get_site_state(state, site_key, site_type):
    """
    サイト単位の State を取得。
    存在しない場合は初期化する。
    """
    sites = state.setdefault("sites", {})

    if site_key not in sites:
        sites[site_key] = {
            # meta = 進捗管理用
            "meta": {
                "type": site_type,
                "last_checked_at": None
            },

            # entries = 実行結果ログ（retry / fallback 管理）
            # key: entry_id (RSSならURL)
            "entries": {}
        }

    return sites[site_key]

def prune_entries(entries, now):
    """
    entries の肥大化防止
    - TTL 超過分を削除
    - 件数上限を超えたら古いものから削除
    """
    cutoff = now - timedelta(days=ENTRY_RETENTION_DAYS)

    # 日付ベース削除
    expired = [
        k for k, v in entries.items()
        if parse_iso(v["first_seen_at"]) < cutoff
    ]
    for k in expired:
        del entries[k]

    # 件数制限
    if len(entries) > ENTRY_MAX:
        ordered = sorted(
            entries.items(),
            key=lambda x: parse_iso(x[1]["first_seen_at"])
        )
        for k, _ in ordered[:-ENTRY_MAX]:
            del entries[k]

# =========================================================
# 共通ユーティリティ
# =========================================================
def cvss_to_severity(score):
    """CVSS スコア → 重要度"""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    return "LOW"

def safe_truncate(text, limit):
    """文字数超過時の安全な切り詰め"""
    return text if len(text) <= limit else text[: limit - 1] + "…"

# =========================================================
# 本文トリミング
# =========================================================
def body_trim(text, site_type=None, max_len=2500):
    """
    Gemini に渡す前の本文整形

    - NVD / JVN:
        脆弱性に関係しそうな行のみ抽出
    - RSS:
        冒頭数行を使用
    """
    if site_type in ("nvd_api", "jvn"):
        lines = [
            l.strip()
            for l in text.splitlines()
            if any(k in l.lower() for k in [
                "allow", "allows", "could", "can",
                "vulnerability", "attack", "execute",
                "disclosure", "denial"
            ])
        ]
        return " ".join(lines)[:max_len]

    lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 10]
    return "\n".join(lines[:6])[:max_len]

# =========================================================
# Gemini 要約
# =========================================================
def summarize(text, api_key, site_type):
    """
    Gemini 要約処理

    戻り値:
      (summary_text, status)

    status:
      - success  : 正常要約
      - fallback : 要約失敗（暫定投稿）
    """
    client = genai.Client(api_key=api_key)

    prompt = (
        """
以下の観点を必ず含め、日本語80文字以内で要約してください。
- 脆弱性の内容
- 影響を受ける対象
- 攻撃者が可能になる行為
※ CVE番号は含めない
"""
        if site_type in ("nvd_api", "jvn")
        else "以下を日本語80文字以内で要約してください。"
    ) + "\n" + text

    for attempt in (1, 2):
        try:
            time.sleep(random.uniform(0.5, 1.5))
            resp = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )
            return resp.text.strip(), "success"

        except Exception as e:
            if attempt == 1 and ("429" in str(e) or "503" in str(e)):
                time.sleep(2)
                continue

            logging.error(f"Gemini summarize failed: {e}")
            return (
                "要約生成に失敗したため、脆弱性の存在のみ通知します。",
                "fallback"
            )

# =========================================================
# 投稿文生成
# =========================================================
def format_post(site, summary, item):
    """Bluesky に投稿する最終テキストを生成"""
    summary = safe_truncate(summary.replace("\n", " "), MAX_POST_LENGTH)

    if site["type"] in ("nvd_api", "jvn"):
        sev = cvss_to_severity(item.get("score", 0))
        return f"{summary}\n{item['id']} | {sev}"

    return summary

# =========================================================
# Bluesky 投稿
# =========================================================
def post_bluesky(client, text, url):
    """Bluesky 投稿"""
    client.send_post(text=text + "\n" + url)

# =========================================================
# Fetch（RSS例）
# =========================================================
def fetch_rss(site):
    """RSS フィード取得"""
    feed = feedparser.parse(site["url"])
    return [{
        "id": e.get("link"),  # RSS は URL を entry_id とする
        "text": f"{e.get('title','')}\n{e.get('summary','')}",
        "url": e.get("link")
    } for e in feed.entries[: site.get("max_items", 1)]]

# =========================================================
# main
# =========================================================
def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    config = yaml.safe_load(open(SITES_FILE, encoding="utf-8"))
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    MODE = settings.get("mode", "test")
    now = utc_now()

    state = load_state()
    gemini_key = os.environ.get("GEMINI_API_KEY")

    # Bluesky ログイン
    if MODE == "prod":
        client = Client()
        client.login(
            os.environ["BLUESKY_IDENTIFIER"],
            os.environ["BLUESKY_PASSWORD"]
        )

    # -----------------------------------------------------
    # サイト単位ループ
    # -----------------------------------------------------
    for site_key, site in sites.items():
        if not site.get("enabled"):
            continue

        logging.info(f"[{site_key}] ---")

        site_state = get_site_state(state, site_key, site["type"])
        entries = site_state["entries"]

        items = fetch_rss(site) if site["type"] == "rss" else []

        for item in items:
            entry_id = item["id"]

            # success は最終状態なので再処理しない
            if entry_id in entries and entries[entry_id]["status"] == "success":
                continue

            prev_entry = entries.get(entry_id)
            prev_status = prev_entry["status"] if prev_entry else None

            # 要約
            trimmed = body_trim(item["text"], site["type"])
            summary, status = summarize(trimmed, gemini_key, site["type"])

            # 投稿文生成
            post_text = format_post(site, summary, item)

            # fallback / failed → success のときのみ再投稿ラベル
            if prev_status in ("fallback", "failed") and status == "success":
                post_text = "【再投稿】" + post_text

            # 投稿
            if MODE == "prod":
                post_bluesky(client, post_text, item["url"])
            else:
                logging.info("[TEST POST]\n" + post_text)

            # entries 更新
            entries[entry_id] = {
                "status": status,
                "first_seen_at": (
                    prev_entry["first_seen_at"] if prev_entry else isoformat(now)
                ),
                "last_tried_at": isoformat(now),
                "retry_count": (
                    prev_entry["retry_count"] + 1 if prev_entry else 1
                ),
                "posted_at": (
                    isoformat(now) if status in ("success", "fallback") else None
                )
            }

        # entries の肥大化防止
        prune_entries(entries, now)

        # 進捗は必ず進める
        site_state["meta"]["last_checked_at"] = isoformat(now)

    if MODE == "prod":
        save_state(state)

if __name__ == "__main__":
    main()
import os
import json
import yaml
import requests
import feedparser
import logging
import time
import random

from google import genai
from atproto import Client, models
from datetime import datetime, timedelta, timezone

# =========================================================
# ■ 設計固定値
# =========================================================
SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"

MAX_POST_LENGTH = 140        # 本文最大140文字
SUMMARY_LIMIT = 80           # 要約最大80文字
POSTED_ID_RETENTION_DAYS = 30
POSTED_ID_MAX = 1000
RETRY_LIMIT = 3

# =========================================================
# ■ 時刻ユーティリティ
# =========================================================
def utc_now():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_iso(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

# =========================================================
# ■ state構造（設計書100％一致）
# =========================================================
def empty_site_state():
    return {
        "last_checked_at": None,
        "posted_ids": {},
        "retry_ids": [],
        "known_cves": [],
        "entries": {}
    }

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

# =========================================================
# ■ posted_ids prune
# =========================================================
def prune_posted_ids(posted_ids, now):
    cutoff = now - timedelta(days=POSTED_ID_RETENTION_DAYS)
    for key in list(posted_ids.keys()):
        if parse_iso(posted_ids[key]) < cutoff:
            del posted_ids[key]
    if len(posted_ids) > POSTED_ID_MAX:
        sorted_items = sorted(posted_ids.items(), key=lambda x: parse_iso(x[1]))
        for key, _ in sorted_items[:-POSTED_ID_MAX]:
            del posted_ids[key]

# =========================================================
# ■ 共通
# =========================================================
def safe_truncate(text, limit):
    return text if len(text) <= limit else text[:limit-1] + "…"

# =========================================================
# ■ Gemini要約（フォールバック区別あり）
# =========================================================
def summarize(text, api_key):
    client = genai.Client(api_key=api_key)
    prompt = f"""
日本語80文字以内で事実のみ要約。
CVE番号は含めない。
{text}
"""
    for attempt in (1, 2):
        try:
            time.sleep(random.uniform(0.5, 1.5))
            resp = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )
            return safe_truncate(resp.text.strip(), SUMMARY_LIMIT), False
        except Exception as e:
            msg = str(e)
            if attempt == 1 and ("429" in msg or "503" in msg):
                # パターンA: API制限はリトライ
                time.sleep(2)
                continue
            break
    # フォールバック文
    return "要約生成に失敗したため、脆弱性の存在のみ通知します。", True

# =========================================================
# ■ RSS取得
# =========================================================
def fetch_rss(site):
    feed = feedparser.parse(site["url"])
    items = []
    for e in feed.entries[: site.get("max_items", 1)]:
        items.append({
            "id": e.get("link"),
            "text": f"{e.get('title','')}\n{e.get('summary','')}",
            "url": e.get("link")
        })
    return items

# =========================================================
# ■ Bluesky投稿（設計準拠 embed専用）
# =========================================================
def post_bluesky(client, text, url):
    # URLは本文に含めず embed として投稿
    embed = models.AppBskyEmbedExternal.Main(
        external=models.AppBskyEmbedExternal.External(
            uri=url,
            title="",
            description=""
        )
    )
    client.send_post(
        text=text,
        embed=embed
    )

# =========================================================
# ■ CVE系URL生成
# =========================================================
def cve_url(source, cve_id):
    if source.lower() == "nvd":
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    elif source.lower() == "jvn":
        return f"https://jvn.jp/vu?id={cve_id}"
    elif source.lower() == "jvd":
        return f"https://jvndb.jvn.jp/contents/{cve_id}.html"
    else:
        return None

# =========================================================
# ■ メイン処理
# =========================================================
def main():
    logging.basicConfig(level=logging.INFO)
    config = yaml.safe_load(open(SITES_FILE, encoding="utf-8"))
    settings = config.get("settings", {})
    sites = config.get("sites", {})
    MODE = settings.get("mode", "test").lower()
    force_test = settings.get("force_test_mode", False)
    skip_first = settings.get("skip_existing_on_first_run", True)

    state = load_state()
    now = utc_now()
    gemini_key = os.environ.get("GEMINI_API_KEY")

    # prodモード時にBlueskyクライアント作成
    client = None
    if MODE == "prod":
        client = Client(base_url="https://bsky.social")
        client.login(
            os.environ["BLUESKY_IDENTIFIER"],
            os.environ["BLUESKY_PASSWORD"]
        )

    for site_key, site in sites.items():
        if not site.get("enabled"):
            continue

        logging.info(f"[{site_key}] ---")
        site_state = state.setdefault(site_key, empty_site_state())

        # 初回スキップ（事故防止）
        if site_state["last_checked_at"] is None and skip_first and MODE == "prod":
            items = fetch_rss(site)
            logging.info(f"初回スキップ {len(items)} 件")
            site_state["last_checked_at"] = iso(now)
            continue

        # ==================================================
        # ① retry_ids 優先処理
        # ==================================================
        retry_queue = site_state["retry_ids"][:RETRY_LIMIT]
        site_state["retry_ids"] = site_state["retry_ids"][RETRY_LIMIT:]
        processing_items = []

        for key in retry_queue:
            entry = site_state["entries"].get(key)
            if entry:
                # 元記事を取得して要約生成
                original_text = entry.get("text", "")
                if not force_test:
                    summary, fallback = summarize(original_text, gemini_key)
                else:
                    summary = safe_truncate(original_text, SUMMARY_LIMIT)
                    fallback = False
                processing_items.append({
                    "id": key,
                    "text": original_text,
                    "url": entry.get("url"),
                    "summary": summary,
                    "fallback": fallback
                })

        # ==================================================
        # ② 通常記事取得
        # ==================================================
        new_items = fetch_rss(site)
        if MODE == "test":
            new_items = new_items[:1]
        for item in new_items:
            # CVE系判定と既知重複チェック
            cve_id = item.get("cve_id")  # RSS以外の場合は適宜設定
            if cve_id and cve_id in site_state["known_cves"]:
                logging.info(f"スキップ済 CVE {cve_id}")
                continue
            processing_items.append(item)

        # ==================================================
        # ③ 投稿処理
        # ==================================================
        for item in processing_items:
            entry_key = item["id"]
            entry = site_state["entries"].setdefault(entry_key, {
                "status": None,
                "retry_count": 0,
                "first_seen_at": iso(now),
                "last_tried_at": None,
                "posted_at": None,
                "reason": "",
                "text": item.get("text", ""),
                "url": item.get("url", "")
            })
            entry["last_tried_at"] = iso(now)

            # Gemini要約
            if "summary" in item:
                summary = item["summary"]
                fallback = item.get("fallback", False)
            else:
                if force_test:
                    summary = safe_truncate(item["text"], SUMMARY_LIMIT)
                    fallback = False
                else:
                    summary, fallback = summarize(item["text"], gemini_key)

            post_text = safe_truncate(summary, MAX_POST_LENGTH)

            # CVE末尾付与
            cve_id = item.get("cve_id")
            if cve_id:
                post_text = f"{post_text}\n{cve_id}"

            # 投稿実行
            try:
                if MODE == "prod":
                    post_bluesky(client, post_text, item["url"])
                    time.sleep(random.randint(30, 90))
                else:
                    logging.info(f"[TEST] {post_text}")

                entry["status"] = "fallback" if fallback else "success"
                entry["posted_at"] = iso(now)
                entry["retry_count"] = 0

                # CVE成功時は known_cves に追加
                if cve_id and entry["status"] == "success":
                    if cve_id not in site_state["known_cves"]:
                        site_state["known_cves"].append(cve_id)

            except Exception as e:
                entry["status"] = "failed"
                entry["retry_count"] += 1
                entry["reason"] = str(e)
                if entry["retry_count"] < RETRY_LIMIT:
                    site_state["retry_ids"].append(entry_key)

        # posted_ids prune
        prune_posted_ids(site_state["posted_ids"], now)
        site_state["last_checked_at"] = iso(now)

    # 永続化
    if MODE == "prod":
        save_state(state)

if __name__ == "__main__":
    main()
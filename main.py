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

# =========================================================
# 定数定義
# =========================================================

SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"
MAX_POST_LENGTH = 140           # 投稿本文の最大文字数（X移植前提）
SUMMARY_HARD_LIMIT = 80         # 要約の安全上限（途切れ防止）

# posted_ids 運用ルール
POSTED_ID_RETENTION_DAYS = 30   # 保持期間（日）
POSTED_ID_MAX = 1000            # 件数上限（安全装置）

# =========================================================
# 時刻ユーティリティ
# =========================================================

def utc_now():
    return datetime.now(timezone.utc)

def isoformat(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

# =========================================================
# 設定 / state 読み込み
# =========================================================

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

# =========================================================
# state 正規化（後方互換吸収）
# =========================================================

def normalize_site_state(site_key, raw_state, now, mode):
    """
    - 旧形式 list → dict に昇格
    - posted_ids を dict(CVE -> posted_at) に統一
    """
    migrated = False

    if raw_state is None:
        return {
            "last_checked_at": None,
            "posted_ids": {}
        }, False

    if isinstance(raw_state, list):
        logging.info(
            f"Migrate state [{site_key}]: list → dict"
            + (" (TEST: not saved)" if mode == "test" else "")
        )
        return {
            "last_checked_at": None,
            "posted_ids": {cid: isoformat(now) for cid in raw_state}
        }, True

    posted = raw_state.get("posted_ids")
    if isinstance(posted, list):
        raw_state["posted_ids"] = {cid: isoformat(now) for cid in posted}
        migrated = True

    raw_state.setdefault("posted_ids", {})

    return raw_state, migrated

# =========================================================
# posted_ids 整理ロジック
# =========================================================

def prune_posted_ids(posted_ids: dict, now: datetime):
    """
    - 保持期間超過削除
    - 件数上限超過時の古い順削除
    """
    before = len(posted_ids)

    # 保持期間超過の削除
    cutoff = now - timedelta(days=POSTED_ID_RETENTION_DAYS)
    expired = [cid for cid, ts in posted_ids.items() if parse_iso(ts) < cutoff]
    for cid in expired:
        del posted_ids[cid]

    # 件数上限超過の削除（古い順）
    if len(posted_ids) > POSTED_ID_MAX:
        logging.warning(
            f"posted_ids exceeded max ({POSTED_ID_MAX}), trimming old entries"
        )
        sorted_items = sorted(posted_ids.items(), key=lambda x: parse_iso(x[1]))
        for cid, _ in sorted_items[:-POSTED_ID_MAX]:
            del posted_ids[cid]

    return before - len(posted_ids)

# =========================================================
# 共通ユーティリティ
# =========================================================

def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

# =========================================================
# 本文前処理
# =========================================================

def body_trim(text, max_len=2500, site_type=None):
    """
    本文の抽出・前処理
    - NVD/JVN は脆弱性関連の文章のみ抽出
    - RSS は6行までを抽出
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
# 投稿文生成（安全トリム＆URL必須）
# =========================================================

def safe_truncate(text: str, limit: int) -> str:
    """文字列を指定長に安全に切り詰める"""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"

def format_post(site, summary, item):
    """
    投稿文生成
    - 本文＋URL＋CVE（NVD/JVNのみ）
    - 最大 MAX_POST_LENGTH 文字で途切れ防止
    """
    url = item.get("url", "")
    url_block = f"\n{url}" if url else ""

    body = summary.replace("\n", " ").strip() + url_block

    # NVD/JVN は CVSS と CVE番号も末尾に追加
    if site["type"] in ("nvd_api", "jvn"):
        score = item.get("score", 0)
        severity = cvss_to_severity(score)
        base_text = f"{body}\nCVSS {score} | {severity}\n{item['id']}"
    else:
        base_text = body

    # 最終安全トリム（X対応）
    return safe_truncate(base_text, MAX_POST_LENGTH)

# =========================================================
# Gemini 要約（80文字安全制限）
# =========================================================

def summarize(text, api_key, site_type=None):
    """
    - NVD/JVN: 脆弱性内容・影響・攻撃手法を必ず含め 80文字以内
    - RSS: 事実のみ簡潔に 80文字以内
    """
    client = genai.Client(api_key=api_key)

    if site_type in ("nvd_api", "jvn"):
        prompt = f"""
以下の観点を必ず含め、日本語80文字以内で要約してください。

- 脆弱性の内容
- 影響を受ける対象
- 攻撃者が可能になる行為

注意:
- CVE番号は含めない
- 不明点は「可能性がある」と表現
- 事実のみ

{text}
"""
    else:
        prompt = f"""
以下を日本語で簡潔に要約してください。
事実のみ。誇張なし。
80文字以内。

{text}
"""

    try:
        resp = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=prompt
        )
        # 安全トリムで80文字程度に収める
        return safe_truncate(resp.text.strip(), SUMMARY_HARD_LIMIT)
    except Exception:
        return "セキュリティ上の問題に関する脆弱性が確認されています。"

# =========================================================
# fetch / post
# =========================================================

def fetch_rss(site, since, until):
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries:
        published = entry.get("published_parsed")
        if not published:
            continue

        entry_time = datetime.fromtimestamp(time.mktime(published), tz=timezone.utc)

        if not (since < entry_time <= until):
            continue

        items.append({
            "id": entry.get("link"),
            "text": f"{entry.get('title','')}\n{entry.get('summary','')}",
            "url": entry.get("link"),
            "entry_time": entry_time
        })

    return items[: site.get("max_items", 1)]

def fetch_nvd(site, start, end):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": site.get("max_items", 50),
        "pubStartDate": isoformat(start),
        "pubEndDate": isoformat(end),
    }

    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    threshold = float(site.get("cvss_threshold", 0))
    items = []

    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cid = cve.get("id")
        metrics = cve.get("metrics", {})

        score = 0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                score = float(metrics[key][0]["cvssData"]["baseScore"])
                break

        if not cid or score < threshold:
            continue

        desc = cve.get("descriptions", [{}])[0].get("value", "")

        items.append({
            "id": cid,
            "score": score,
            "text": desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}"
        })

    return items

def fetch_jvn(site, since, until):
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries:
        if not entry.get("published_parsed"):
            continue

        entry_time = datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)

        if not (since < entry_time <= until):
            continue

        cve_ids = [t for t in entry.get("tags", []) if t.get("term", "").startswith("CVE-")]
        if not cve_ids:
            continue

        items.append({
            "id": cve_ids[0]["term"],
            "score": site.get("default_cvss", 0),
            "text": entry.get("summary", ""),
            "url": entry.get("link"),
            "entry_time": entry_time
        })

    return items[: site.get("max_items", 1)]

def post_bluesky(client, text, url):
    client.send_post(text=text)

# =========================================================
# main
# =========================================================

def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    config = load_config()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    MODE = settings.get("mode", "test").lower()
    force_test = settings.get("force_test_mode", False)
    skip_first = settings.get("skip_existing_on_first_run", True)

    original_state = load_state()
    state = json.loads(json.dumps(original_state))
    state_dirty = False

    now = utc_now()
    gemini_key = os.environ.get("GEMINI_API_KEY")

    if MODE == "prod":
        client = Client()
        client.login(
            os.environ.get("BLUESKY_IDENTIFIER"),
            os.environ.get("BLUESKY_PASSWORD"),
        )

    for site_key, site in sites.items():
        if not site.get("enabled"):
            continue

        # state 正規化（posted_ids list → dict 等）
        site_state, migrated = normalize_site_state(site_key, state.get(site_key), now, MODE)
        state[site_key] = site_state
        if migrated and MODE == "prod":
            state_dirty = True

        posted_ids = site_state["posted_ids"]
        last_checked = site_state.get("last_checked_at")

        # 初回実行時は既存分スキップ
        if not last_checked:
            if skip_first and MODE == "prod":
                site_state["last_checked_at"] = isoformat(now)
                state_dirty = True
                logging.info(f"No new items for [{site_key}] (initial run skipped)")
                continue
            since = now - timedelta(days=1)
        else:
            since = parse_iso(last_checked)

        until = now

        # データ取得
        if site["type"] == "rss":
            items = fetch_rss(site, since, until)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site, since, until)
        elif site["type"] == "jvn":
            items = fetch_jvn(site, since, until)
        else:
            continue

        if not items:
            logging.info(f"No new items found for [{site_key}] between {since} and {until}")
            continue

        for item in items:
            cid = item.get("id")
            if cid in posted_ids:
                continue

            # 本文抽出 → 要約 → 投稿文生成
            trimmed = body_trim(item["text"], site_type=site["type"])
            summary = trimmed[:SUMMARY_HARD_LIMIT] if force_test else summarize(trimmed, gemini_key, site["type"])
            post_text = format_post(site, summary, item)

            # testモードではログ出力のみ
            if MODE == "test":
                logging.info("[TEST]\n" + post_text)
            else:
                # 本番投稿
                post_bluesky(client, post_text, item["url"])
                logging.info(f"Posted new item for [{site_key}]: {cid}")

            # posted_id 追加
            posted_ids[cid] = isoformat(now)
            logging.info(f"Added posted_id: {cid}")

            # prune 適用
            pruned = prune_posted_ids(posted_ids, now)
            if pruned > 0:
                logging.info(f"Pruned {pruned} old posted_ids for [{site_key}]")

            time.sleep(random.randint(30, 90))  # 投稿間隔ランダム

        site_state["last_checked_at"] = isoformat(now)
        state_dirty = True

    # state 保存
    if MODE == "prod" and state_dirty:
        save_state(state)

if __name__ == "__main__":
    main()
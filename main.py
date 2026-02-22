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

# ==========================
# 時刻ユーティリティ
# ==========================

def utc_now():
    return datetime.now(timezone.utc)

def isoformat(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_iso(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

# ==========================
# 設定 / state
# ==========================

def load_config():
    with open(SITES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_state():
    """
    state は以下の構造を想定：

    {
      "nvd": {
        "last_checked_at": "...",
        "posted_ids": ["CVE-...."]
      },
      "jvn": {
        "last_checked_at": "...",
        "posted_ids": []
      }
    }
    """
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
# CVSS ユーティリティ
# ==========================

def cvss_to_severity(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

# ==========================
# posted CVE 横断収集
# ==========================

def collect_posted_cves(state: dict) -> set:
    """
    全サイト横断で、すでに投稿済みの CVE ID を収集する

    - NVD → JVN → JVD などを跨いだ重複防止用
    - test モードでも参照はするが、保存は prod のみ
    """
    cves = set()
    for site_state in state.values():
        for cid in site_state.get("posted_ids", []):
            if isinstance(cid, str) and cid.startswith("CVE-"):
                cves.add(cid)
    return cves

# ==========================
# 本文前処理
# ==========================

def body_trim(text, max_len=2500, site_type=None):
    """
    Gemini に渡す前の本文前処理

    - NVD: 意味のある文だけ抽出
    - RSS/JVN: 従来どおり
    """
    if site_type == "nvd_api":
        lines = [
            l.strip()
            for l in text.splitlines()
            if any(k in l.lower() for k in [
                "allow", "allows", "could", "can",
                "vulnerability", "attack", "execute",
                "disclosure", "denial"
            ])
        ]
        joined = " ".join(lines)
        return joined[:max_len]

    lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 10]
    return "\n".join(lines[:6])[:max_len]

# ==========================
# 投稿文生成
# ==========================

def format_post(site, summary, url, item):
    """
    タイトル・分類は使わない。
    本文で「何が起きるか」が分かる前提。
    """
    body = summary.replace("\n", " ").strip()

    if site["type"] == "nvd_api":
        score = item.get("score", 0)
        severity = cvss_to_severity(score)

        text = (
            f"{body}\n\n"
            f"CVSS {score} | {severity}\n"
            f"{item['id']}"
        )
    else:
        text = body

    if len(text) > MAX_POST_LENGTH:
        text = text[:MAX_POST_LENGTH - 1] + "…"

    return text

# ==========================
# Gemini 要約
# ==========================

def summarize(text, api_key, site_type=None, max_retries=3):
    client = genai.Client(api_key=api_key)

    if site_type == "nvd_api":
        prompt = f"""
以下の観点を必ず含め、日本語80〜100文字で要約してください。

- 脆弱性の内容
- 影響を受ける対象
- 攻撃者が可能になる行為

注意:
- CVE番号は含めない
- 不明な点は「可能性がある」と表現
- 事実のみ

{text}
"""
    else:
        prompt = f"""
以下を日本語で簡潔に要約してください。
事実のみ。誇張なし。
100文字以内。

{text}
"""

    for i in range(max_retries):
        try:
            resp = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )
            if resp.text:
                return resp.text.strip()[:100]
        except Exception:
            time.sleep(random.randint(30, 90))

    # LLM失敗時の保険
    return "影響内容が確認されていますが、詳細は現在調査中です。"

# ==========================
# RSS / JVN
# ==========================

def fetch_rss(site, since, until):
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries:
        published = entry.get("published_parsed")
        if not published:
            continue

        entry_time = datetime.fromtimestamp(
            time.mktime(published),
            tz=timezone.utc
        )

        if not (since < entry_time <= until):
            continue

        items.append({
            "id": entry.get("cve_id") or entry.get("id"),
            "text": f"{entry.get('title','')}\n{entry.get('summary','')}",
            "url": entry.get("link"),
        })

    return items[: site.get("max_items", 1)]

# ==========================
# NVD
# ==========================

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
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

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

# ==========================
# Bluesky 投稿
# ==========================

def post_bluesky(client, text, url):
    try:
        resp = requests.get(
            "https://cardyb.bsky.app/v1/extract",
            params={"url": url},
            timeout=10
        )
        card = resp.json()

        embed = models.AppBskyEmbedExternal.Main(
            external=models.AppBskyEmbedExternal.External(
                uri=url,
                title=card.get("title", ""),
                description=card.get("description", "")
            )
        )
        client.send_post(text=text, embed=embed)
    except Exception:
        client.send_post(text=text)

# ==========================
# main
# ==========================

def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    config = load_config()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    MODE = settings.get("mode", "test").lower()
    force_test = settings.get("force_test_mode", False)
    skip_first = settings.get("skip_existing_on_first_run", True)

    original_state = load_state()
    state = json.loads(json.dumps(original_state))  # deep copy
    state_dirty = False

    # --- 既存投稿済み CVE を横断収集 ---
    posted_cves = collect_posted_cves(state)

    gemini_key = os.environ.get("GEMINI_API_KEY")

    if MODE == "prod":
        client = Client(base_url="https://bsky.social")
        client.login(
            os.environ["BLUESKY_IDENTIFIER"],
            os.environ["BLUESKY_PASSWORD"]
        )

    now = utc_now()

    for key, site in sites.items():
        if not site.get("enabled"):
            continue

        logging.info(f"Processing: {key}")
        site_state = state.setdefault(key, {})

        last_checked = site_state.get("last_checked_at")
        if not last_checked and skip_first:
            logging.info(f"{key}: initial run → skip existing")
            site_state["last_checked_at"] = isoformat(now)
            if MODE == "prod":
                state_dirty = True
            continue

        since = parse_iso(last_checked) if last_checked else now - timedelta(days=1)

        # --- fetch ---
        if site["type"] == "nvd_api":
            items = fetch_nvd(site, since, now)
        else:
            items = fetch_rss(site, since, now)

        for item in items:
            cve_id = item.get("id")

            # ===== CVE 重複防止 =====
            if cve_id and cve_id in posted_cves:
                logging.info(f"skip duplicate CVE: {cve_id}")
                continue

            summary = (
                item["text"][:100]
                if force_test
                else summarize(
                    body_trim(item["text"], site_type=site["type"]),
                    gemini_key,
                    site["type"]
                )
            )

            post_text = format_post(site, summary, item["url"], item)

            if MODE == "test":
                logging.info("[TEST]\n" + post_text)
                continue

            post_bluesky(client, post_text, item["url"])

            # --- 投稿成功後に CVE を記録 ---
            if cve_id:
                site_state.setdefault("posted_ids", []).append(cve_id)
                posted_cves.add(cve_id)

            time.sleep(random.randint(30, 90))

        site_state["last_checked_at"] = isoformat(now)
        if MODE == "prod":
            state_dirty = True

    if MODE == "prod" and state_dirty:
        save_state(state)

if __name__ == "__main__":
    main()
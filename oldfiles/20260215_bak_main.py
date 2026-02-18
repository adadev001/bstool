import os
import json
import requests
import yaml
import feedparser
import logging
import time
import random
from datetime import datetime, timezone, timedelta
from google import genai
from atproto import Client, models

# ==========================
# 定数
# ==========================

SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"
MAX_POST_LENGTH = 140

JST = timezone(timedelta(hours=9))  # --- JST LOG ADDITION ---

# ==========================
# JST対応ログ用ユーティリティ
# ==========================

def utc_jst_str(ts: float | None = None) -> str:
    """
    UTC を基準にし、ログ表示のみ JST を併記する
    """
    if ts is None:
        dt_utc = datetime.now(timezone.utc)
    else:
        dt_utc = datetime.fromtimestamp(ts, timezone.utc)

    dt_jst = dt_utc.astimezone(JST)
    return f"{dt_utc.isoformat()} (JST: {dt_jst.isoformat()})"

# ==========================
# 設定読み込み
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
        except:
            return {}

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

def cvss_to_severity(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

def format_post(site, summary, url, item):
    body = summary.replace("\n", " ").strip()

    if site["type"] == "nvd_api":
        cve_id = item["id"]
        score = item.get("score", 0)
        severity = cvss_to_severity(score)

        header = f"{cve_id}"
        score_line = f"CVSS {score} | {severity}"
        base_text = f"{header}\n{score_line}\n\n{body}"
    else:
        base_text = body

    if len(base_text) > MAX_POST_LENGTH:
        base_text = base_text[:MAX_POST_LENGTH - 2] + "…"

    return base_text

# ==========================
# Gemini 要約
# ==========================

def summarize(text, api_key, max_retries=3):
    client = genai.Client(api_key=api_key)

    prompt = f"""
以下を日本語で簡潔に要約してください。
事実のみ。
誇張なし。
100文字以内。

{text}
"""

    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )

            result = response.text.strip()
            if result:
                return result[:100]

        except Exception:
            if attempt < max_retries - 1:
                time.sleep(random.randint(30, 90))
            else:
                raise

    return text[:100]

# ==========================
# RSS取得
# ==========================

def fetch_rss(site):
    logging.debug(f"[fetch_rss] start at {utc_jst_str()}")  # --- JST LOG ADDITION ---
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries[:site.get("max_items", 50)]:
        link = entry.get("link")
        title = entry.get("title", "")
        summary = entry.get("summary", "")

        if not link:
            continue

        items.append({
            "id": link,
            "text": f"{title}\n{summary}",
            "url": link
        })

    logging.debug(f"[fetch_rss] fetched={len(items)} at {utc_jst_str()}")  # --- JST LOG ADDITION ---
    return items

# ==========================
# NVD API取得
# ==========================

def fetch_nvd(site):
    logging.debug(f"[fetch_nvd] start at {utc_jst_str()}")  # --- JST LOG ADDITION ---
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"resultsPerPage": site.get("max_items", 100)}

    response = requests.get(url, params=params)
    response.raise_for_status()
    data = response.json()

    items = []
    threshold = float(site.get("cvss_threshold", 0))

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        metrics = cve.get("metrics", {})

        score = 0
        if "cvssMetricV31" in metrics:
            score = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV30" in metrics:
            score = float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV2" in metrics:
            score = float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])

        if score < threshold:
            continue

        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value")
                break

        if not cve_id:
            continue

        items.append({
            "id": cve_id,
            "score": score,
            "text": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        })

    logging.debug(f"[fetch_nvd] fetched={len(items)} at {utc_jst_str()}")  # --- JST LOG ADDITION ---
    return items

# ==========================
# Bluesky投稿
# ==========================

def post_bluesky(client, text, url):
    logging.info(f"[post] start at {utc_jst_str()}")  # --- JST LOG ADDITION ---
    try:
        client.send_post(text=text)
        logging.info(f"[post] completed at {utc_jst_str()}")  # --- JST LOG ADDITION ---
    except Exception as e:
        logging.error(f"[post] failed at {utc_jst_str()} error={e}")  # --- JST LOG ADDITION ---
        raise

# ==========================
# メイン処理
# ==========================

def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s:%(message)s"
    )

    logging.info(f"Program start at {utc_jst_str()}")  # --- JST LOG ADDITION ---

    gemini_key = os.environ.get("GEMINI_API_KEY")
    bluesky_id = os.environ.get("BLUESKY_IDENTIFIER")
    bluesky_pw = os.environ.get("BLUESKY_PASSWORD")

    if not bluesky_id or not bluesky_pw:
        raise ValueError("Bluesky credentials not set")
    if not gemini_key:
        raise ValueError("GEMINI_API_KEY not set")

    client = Client(base_url="https://bsky.social")
    client.login(bluesky_id, bluesky_pw)

    config = load_config()
    settings = config.get("settings", {})
    force_test = settings.get("force_test_mode", False)
    sites = config.get("sites", {})

    def get_summary(text):
        return text[:200] if force_test else summarize(text, gemini_key)

    state = load_state()
    if "_posted_cves" not in state:
        state["_posted_cves"] = []

    skip_first = settings.get("skip_existing_on_first_run", True)

    for site_key, site in sites.items():
        if not site.get("enabled", True):
            continue

        if site_key not in state:
            state[site_key] = []

        logging.info(f"[site] {site_key} start at {utc_jst_str()}")  # --- JST LOG ADDITION ---

        if site["type"] == "rss":
            items = fetch_rss(site)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site)
        else:
            continue

        if not state[site_key] and skip_first:
            logging.info("Initial run → skip existing")
            state[site_key] = [item["id"] for item in items]
            continue

        new_items = [item for item in items if item["id"] not in state[site_key]]

        for item in new_items:
            summary = get_summary(item["text"])
            post_text = format_post(site, summary, item["url"], item)
            post_bluesky(client, post_text, item["url"])

            state[site_key].append(item["id"])
            save_state(state)

    logging.info(f"Program end at {utc_jst_str()}")  # --- JST LOG ADDITION ---

if __name__ == "__main__":
    main()

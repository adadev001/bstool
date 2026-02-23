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
SUMMARY_HARD_LIMIT = 80
POSTED_ID_RETENTION_DAYS = 30
POSTED_ID_MAX = 1000

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
# 共通ユーティリティ
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

def body_trim(text, max_len=2500, site_type=None):
    if site_type in ("nvd_api", "jvn"):
        lines = [l.strip() for l in text.splitlines() if any(k in l.lower() for k in [
            "allow", "allows", "could", "can",
            "vulnerability", "attack", "execute",
            "disclosure", "denial"
        ])]
        return " ".join(lines)[:max_len]
    lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 10]
    return "\n".join(lines[:6])[:max_len]

def safe_truncate(text, limit):
    return text if len(text) <= limit else text[: limit - 1] + "…"

# ==========================
# 投稿文生成（良いとこ取り版）
# ==========================
def format_post(site, summary, item):
    """本文切り出し後にURLを必ず末尾に付与、NVD/JVNはCVE+CVSSも表示"""
    body = summary.replace("\n", " ").strip()

    if site["type"] in ("nvd_api", "jvn"):
        cve_id = item["id"]
        score = item.get("score", 0)
        severity = cvss_to_severity(score)
        base_text = f"{body}\n{cve_id} CVSS {score} | {severity}\n{item['url']}"
    else:
        base_text = f"{body}\n{item.get('url','')}"

    return safe_truncate(base_text, MAX_POST_LENGTH)

# ==========================
# Gemini 要約
# ==========================
def summarize(text, api_key, site_type=None, max_retries=3):
    client = genai.Client(api_key=api_key)
    prompt = f"""
以下の観点を必ず含め、日本語{SUMMARY_HARD_LIMIT}文字以内で要約してください。
{text}
"""
    for attempt in range(max_retries):
        try:
            resp = client.models.generate_content(model="gemini-2.5-flash-lite", contents=prompt)
            result = resp.text.strip()
            if result:
                return safe_truncate(result, SUMMARY_HARD_LIMIT)
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(random.randint(30, 90))
            else:
                return text[:SUMMARY_HARD_LIMIT]
    return text[:SUMMARY_HARD_LIMIT]

# ==========================
# fetch
# ==========================
def fetch_rss(site, since=None, until=None):
    feed = feedparser.parse(site["url"])
    items = []
    for entry in feed.entries[:site.get("max_items",1)]:
        link = entry.get("link")
        if not link:
            continue
        items.append({
            "id": link,
            "text": f"{entry.get('title','')}\n{entry.get('summary','')}",
            "url": link
        })
    return items

def fetch_nvd(site, start, end):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": site.get("max_items",50),
        "pubStartDate": isoformat(start),
        "pubEndDate": isoformat(end),
    }
    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    threshold = float(site.get("cvss_threshold",0))
    items = []
    for v in data.get("vulnerabilities",[]):
        cve = v.get("cve",{})
        cid = cve.get("id")
        metrics = cve.get("metrics",{})
        score = 0
        for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if key in metrics:
                score = float(metrics[key][0]["cvssData"]["baseScore"])
                break
        if not cid or score < threshold:
            continue
        desc = cve.get("descriptions",[{}])[0].get("value","")
        items.append({
            "id": cid,
            "score": score,
            "text": desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}"
        })
    return items

# ==========================
# Bluesky 投稿（URL embed対応）
# ==========================
def post_bluesky(client, text, url):
    try:
        resp = requests.get("https://cardyb.bsky.app/v1/extract", params={"url":url}, timeout=10)
        card = resp.json()
        image_blob = None
        image_url = card.get("image")
        if image_url:
            img = requests.get(image_url, timeout=10)
            if img.status_code == 200 and len(img.content) < 1_000_000:
                upload = client.upload_blob(img.content)
                image_blob = upload.blob
        embed = models.AppBskyEmbedExternal.Main(
            external=models.AppBskyEmbedExternal.External(
                uri=url,
                title=card.get("title", ""),
                description=card.get("description", ""),
                thumb=image_blob
            )
        )
        client.send_post(text=text, embed=embed)
    except Exception as e:
        logging.warning(f"Embed failed: {e}")
        client.send_post(text=text)

# ==========================
# main
# ==========================
def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    config = load_config()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    MODE = settings.get("mode","test").lower()
    force_test = settings.get("force_test_mode", False)
    skip_first = settings.get("skip_existing_on_first_run", True)

    state = json.loads(json.dumps(load_state()))
    state_dirty = False
    now = utc_now()
    gemini_key = os.environ.get("GEMINI_API_KEY")

    client = None
    if MODE == "prod":
        client = Client(base_url="https://bsky.social")
        client.login(os.environ.get("BLUESKY_IDENTIFIER"), os.environ.get("BLUESKY_PASSWORD"))

    for site_key, site in sites.items():
        if not site.get("enabled",False):
            continue

        site_state = state.setdefault(site_key, {"posted_ids": {}})
        posted_ids = site_state.setdefault("posted_ids", {})

        last_checked = site_state.get("last_checked_at")
        since = parse_iso(last_checked) if last_checked else now - timedelta(days=1)
        until = now

        if site["type"] == "rss":
            items = fetch_rss(site, since, until)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site, since, until)
        else:
            continue

        for item in items:
            cid = item["id"]
            if cid in posted_ids:
                continue

            trimmed = body_trim(item["text"], site_type=site["type"])
            summary = trimmed[:SUMMARY_HARD_LIMIT] if force_test else summarize(trimmed, gemini_key, site_type=site["type"])
            post_text = format_post(site, summary, item)

            if MODE == "test":
                logging.info(f"[TEST] {post_text}")
            else:
                post_bluesky(client, post_text, item["url"])
                time.sleep(random.randint(30,90))

            posted_ids[cid] = isoformat(now)
            state_dirty = True

        site_state["last_checked_at"] = isoformat(now)

    if MODE == "prod" and state_dirty:
        save_state(state)

if __name__ == "__main__":
    main()

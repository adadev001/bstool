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
# 時刻ユーティリティ（NVD 用）
# ==========================

def utc_now():
    return datetime.now(timezone.utc)

def isoformat(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


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


def format_post(site, summary, url, item):
    body = summary.replace("\n", " ").strip()

    if site["type"] == "nvd_api":
        cve_id = item["id"]
        score = item.get("score", 0)
        severity = cvss_to_severity(score)

        base_text = (
            f"{cve_id}\n"
            f"CVSS {score} | {severity}\n\n"
            f"{body}"
        )
    else:
        base_text = body

    if len(base_text) > MAX_POST_LENGTH:
        base_text = base_text[:MAX_POST_LENGTH - 1] + "…"

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
主語と固有名詞を省略しない。
100文字以内。

{text}
"""

    for attempt in range(max_retries):
        try:
            resp = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )
            result = resp.text.strip()
            if result:
                return result[:100]
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(random.randint(30, 90))
            else:
                raise

    return text[:100]


# ==========================
# RSS
# ==========================

def fetch_rss(site):
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries[:site.get("max_items", 1)]:
        link = entry.get("link")
        if not link:
            continue

        items.append({
            "id": link,
            "text": f"{entry.get('title','')}\n{entry.get('summary','')}",
            "url": link
        })

    return items


# ==========================
# NVD（期間指定）
# ==========================

def fetch_nvd(site, pub_start, pub_end):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "resultsPerPage": site.get("max_items", 50),
        "pubStartDate": isoformat(pub_start),
        "pubEndDate": isoformat(pub_end),
    }

    logging.info(
        f"NVD query: {params['pubStartDate']} → {params['pubEndDate']}"
    )

    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    threshold = float(site.get("cvss_threshold", 0))
    items = []

    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        metrics = cve.get("metrics", {})

        score = 0
        if "cvssMetricV31" in metrics:
            score = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV30" in metrics:
            score = float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV2" in metrics:
            score = float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])

        if not cve_id or score < threshold:
            continue

        items.append({
            "id": cve_id,
            "score": score,
            "text": cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
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

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s:%(message)s"
    )

    config = load_config()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    MODE = settings.get("mode", "test").lower()
    force_test = settings.get("force_test_mode", False)
    skip_first = settings.get("skip_existing_on_first_run", True)

    state = load_state()

    # --- Gemini / Bluesky ---
    gemini_key = os.environ.get("GEMINI_API_KEY")
    bluesky_id = os.environ.get("BLUESKY_IDENTIFIER")
    bluesky_pw = os.environ.get("BLUESKY_PASSWORD")

    if MODE == "prod":
        client = Client(base_url="https://bsky.social")
        client.login(bluesky_id, bluesky_pw)

    def get_summary(text):
        return text[:200] if force_test else summarize(text, gemini_key)

    # ==========================
    # NVD 期間決定（唯一）
    # ==========================

    now = utc_now()

    if "last_checked_at" not in state:
        logging.info("Initial NVD run → last 1 day")
        pub_start = now - timedelta(days=1)
    else:
        pub_start = datetime.fromisoformat(
            state["last_checked_at"].replace("Z", "+00:00")
        )

    pub_end = now

    # ==========================
    # サイト処理
    # ==========================

    state.setdefault("_posted_cves", [])

    for site_key, site in sites.items():

        if not site.get("enabled", False):
            continue

        state.setdefault(site_key, [])

        logging.info(f"Processing: {site_key}")

        if site["type"] == "rss":
            items = fetch_rss(site)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site, pub_start, pub_end)
        else:
            continue

        if MODE == "test":
            if items:
                item = items[0]
                summary = get_summary(item["text"])
                post_text = format_post(site, summary, item["url"], item)
                logging.info("[TEST]\n" + post_text)
            continue

        # --- prod ---
        if not state[site_key] and skip_first:
            logging.info("Initial run → skip existing")
            state[site_key] = [item["id"] for item in items]
            continue

        for item in items:
            if item["id"] in state[site_key]:
                continue

            if site_key == "jvn" and item["id"] in state["_posted_cves"]:
                continue

            summary = get_summary(item["text"])
            post_text = format_post(site, summary, item["url"], item)

            post_bluesky(client, post_text, item["url"])
            time.sleep(random.randint(30, 90))

            state[site_key].append(item["id"])

            if site_key == "nvd":
                state["_posted_cves"].append(item["id"])

    # ==========================
    # state 更新（正常終了時のみ）
    # ==========================

    if MODE == "prod":
        state["last_checked_at"] = isoformat(now)
        save_state(state)


if __name__ == "__main__":
    main()

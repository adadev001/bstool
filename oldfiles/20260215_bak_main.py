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

# ★ JST対応
JST = timezone(timedelta(hours=9))

def format_utc_with_jst(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    utc_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    jst_str = dt.astimezone(JST).strftime("%Y-%m-%d %H:%M:%S")
    return f"{utc_str}（JST：{jst_str}）"


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


# ==========================
# 補助
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
        base_text = f"{cve_id}\nCVSS {score} | {severity}\n\n{body}"
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
            if response.text:
                return response.text.strip()[:100]
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
    feed = feedparser.parse(site["url"])
    items = []
    now_utc = datetime.now(timezone.utc)

    for entry in feed.entries[:site.get("max_items", 50)]:
        link = entry.get("link")
        if not link:
            continue

        published_at = None
        if entry.get("published_parsed"):
            published_at = datetime.fromtimestamp(
                time.mktime(entry.published_parsed),
                tz=timezone.utc
            )

        items.append({
            "id": link,
            "text": f"{entry.get('title', '')}\n{entry.get('summary', '')}",
            "url": link,
            "published_at": published_at,
            "fetched_at": now_utc
        })

    return items


# ==========================
# NVD API取得
# ==========================

def fetch_nvd(site):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"resultsPerPage": site.get("max_items", 100)}
    response = requests.get(url, params=params)
    response.raise_for_status()
    data = response.json()

    items = []
    now_utc = datetime.now(timezone.utc)
    threshold = float(site.get("cvss_threshold", 0))

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        published_raw = cve.get("published")
        published_at = (
            datetime.fromisoformat(published_raw.replace("Z", "+00:00"))
            if published_raw else None
        )

        score = 0
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                score = float(metrics[key][0]["cvssData"]["baseScore"])
                break

        if score < threshold:
            continue

        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )

        items.append({
            "id": cve_id,
            "score": score,
            "text": f"{cve_id}\nCVSS {score}\n\n{desc}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published_at": published_at,
            "fetched_at": now_utc
        })

    return items


# ==========================
# Bluesky投稿
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

        if card.get("image"):
            img = requests.get(card["image"], timeout=10)
            if img.status_code == 200 and len(img.content) < 1_000_000:
                image_blob = client.upload_blob(img.content).blob

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
# メイン処理
# ==========================

def main():

    logging.basicConfig(
        level=logging.DEBUG,  # ★ DEBUGまでJST併記
        format="%(levelname)s:%(message)s"
    )

    gemini_key = os.environ.get("GEMINI_API_KEY")
    bluesky_id = os.environ.get("BLUESKY_IDENTIFIER")
    bluesky_pw = os.environ.get("BLUESKY_PASSWORD")

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

    for site_key, site in sites.items():

        if not site.get("enabled", True):
            continue

        logging.info(f"Processing: {site_key}")

        items = (
            fetch_rss(site) if site["type"] == "rss"
            else fetch_nvd(site) if site["type"] == "nvd_api"
            else []
        )

        for item in items:

            if item.get("published_at"):
                logging.debug(
                    f"published_at = {format_utc_with_jst(item['published_at'])}"
                )

            logging.debug(
                f"fetched_at   = {format_utc_with_jst(item['fetched_at'])}"
            )

            summary = get_summary(item["text"])
            post_text = format_post(site, summary, item["url"], item)

            post_bluesky(client, post_text, item["url"])
            posted_at = datetime.now(timezone.utc)

            logging.info(
                f"posted_at    = {format_utc_with_jst(posted_at)}"
            )

            time.sleep(random.randint(30, 90))

    save_state(state)


if __name__ == "__main__":
    main()

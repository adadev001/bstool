import os
import json
import requests
import yaml
import feedparser
import logging
import time
from google import genai
from atproto import Client, models

# ==========================
# 定数
# ==========================

SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"
MAX_POST_LENGTH = 140


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

        # itemにscoreを直接持たせる方が安全
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

        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                raise e

    return text[:100]


# ==========================
# RSS取得
# ==========================

def fetch_rss(site):
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

    return items


# ==========================
# NVD API取得
# ==========================

def fetch_nvd(site):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "resultsPerPage": site.get("max_items", 100),
        "sortBy": "publishDate",
        "sortOrder": "desc"
    }

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

        # --- CVSSバージョン対応 ---
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

        detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        items.append({
             "id": cve_id,
             "score": score,
             "text": (
                f"CVE ID: {cve_id}\n"
                f"CVSS Score: {score}\n\n"
                f"Description:\n"
                f"{description}"
            ),
            "url": detail_url
        })

    return items


# ==========================
# Bluesky投稿
# ==========================

def post_bluesky(identifier, password, text, url):
    client = Client()
    client.login(identifier, password)

    try:
        # --- card情報取得 ---
        resp = requests.get(
            "https://cardyb.bsky.app/v1/extract",
            params={"url": url},
            timeout=10
        )
        card = resp.json()

        image_blob = None

        # --- 画像がある場合 ---
        image_url = card.get("image")
        if image_url:
            img_resp = requests.get(image_url, timeout=10)

            if img_resp.status_code == 200:

                # 1MB以上はアップロードしない
                if len(img_resp.content) < 1_000_000:
                    upload = client.upload_blob(img_resp.content)
                    image_blob = upload.blob
                else:
                    logging.info("Image too large, skipping thumbnail")

        # --- embed生成 ---
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
        level=logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s"
    )

    gemini_key = os.environ.get("GEMINI_API_KEY")
    bluesky_id = os.environ.get("BLUESKY_IDENTIFIER")
    bluesky_pw = os.environ.get("BLUESKY_PASSWORD")

    if not bluesky_id or not bluesky_pw:
        raise ValueError("Bluesky credentials not set")

    if not gemini_key:
        raise ValueError("GEMINI_API_KEY not set")

    # ==========================
    # ★ 1件だけ実データ投稿テスト
    # ==========================
    TEST_SINGLE_POST = True
    TEST_SITE_KEY = "nvd"   # ← ここを変更するだけで切替

    if TEST_SINGLE_POST:
        logging.info("Test single real item")

        config = load_config()
        sites = config.get("sites", {})

        if TEST_SITE_KEY not in sites:
            raise ValueError(f"{TEST_SITE_KEY} not found in sites.yaml")

        site = sites[TEST_SITE_KEY]

        if not site.get("enabled", True):
            raise ValueError(f"{TEST_SITE_KEY} is disabled")

        if site["type"] == "rss":
            items = fetch_rss(site)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site)
        else:
            raise ValueError("Unknown site type")

        if not items:
            logging.info("No items found")
            return

        item = items[0]

        summary = summarize(item["text"], gemini_key)
        post_text = format_post(site, summary, item["url"], item)

        post_bluesky(
            bluesky_id,
            bluesky_pw,
            post_text,
            item["url"]
        )

        logging.info("Posted successfully")

        return


    config = load_config()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    state = load_state()

    if not gemini_key:
        raise ValueError("GEMINI_API_KEY not set")

    skip_first = settings.get("skip_existing_on_first_run", True)
    force_test = settings.get("force_test_mode", False)

    for site_key, site in sites.items():

        if not site.get("enabled", True):
            continue

        if site_key not in state:
            state[site_key] = []

        logging.info(f"Processing: {site_key}")

        if site["type"] == "rss":
            items = fetch_rss(site)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site)
        else:
            logging.warning(f"Unknown type: {site['type']}")
            continue

        # 初回処理
        if not state[site_key] and skip_first:
            logging.info("Initial run → skip existing")
            state[site_key] = [item["id"] for item in items]
            continue

        new_items = [
            item for item in items
            if item["id"] not in state[site_key]
        ]

        if not new_items:
            logging.info("No new items")
            continue

        # 新着を投稿
        for item in new_items:

            summary = summarize(item["text"], gemini_key)
            post_text = format_post(site, summary, item["url"], item)

            if force_test:
                logging.info("[TEST MODE] " + post_text)
            else:
                post_bluesky(bluesky_id, bluesky_pw, post_text, item["url"])
                time.sleep(2)
                logging.info("Posted successfully")

            state[site_key].append(item["id"])

        save_state(state)

if __name__ == "__main__":
    main()

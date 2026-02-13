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


def format_post(site, summary, url, item):
    body = summary.replace("\n", " ").strip()

    if site["type"] == "nvd_api":
        cve_id = item["id"]

        header = cve_id

        if "CVSS:" in item["text"]:
            score_part = item["text"].split("CVSS:")[1].split(")")[0]
            header += f" (CVSS:{score_part})"

        base_text = f"{header}\n{body}"
    else:
        base_text = body

    allowed = MAX_POST_LENGTH

    if len(base_text) > allowed:
        base_text = base_text[:allowed - 1] + "…"

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
            return response.text.strip()

        except Exception:
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
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
        "resultsPerPage": site.get("max_items", 50),
    }

    response = requests.get(url, params=params)
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
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        if score < threshold:
            continue

        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value")
                break

        if not cve_id:
            continue

        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        items.append({
            "id": cve_id,
            "text": f"{cve_id} (CVSS:{score})\n{description}",
            "url": url
        })

    return items


# ==========================
# Bluesky投稿
# ==========================

def post_bluesky(identifier, password, text, url):
    client = Client()
    client.login(identifier, password)

    # リンクカード生成
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
                description=card.get("description", ""),
                thumb=None
            )
        )

        client.send_post(text=text, embed=embed)

    except Exception:
        # embed失敗時はフォールバック
        client.send_post(text=text)



# ==========================
# メイン処理
# ==========================

惜しいです。
今のコードは インデントが壊れています。

if TEST_SINGLE_POST: が main() の外に出ています。
そのままだと構文的にも論理的にも正しく動きません。

✅ 正しい構造

TEST_SINGLE_POST ブロックは main() の中 に入れてください。

🔧 修正版（そのまま置き換えOK）
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

    if TEST_SINGLE_POST:
        logging.info("Test single real item")

        config = load_config()
        sites = config.get("sites", {})

        for site_key, site in sites.items():
            if not site.get("enabled", True):
                continue

            if site["type"] == "rss":
                items = fetch_rss(site)
            elif site["type"] == "nvd_api":
                items = fetch_nvd(site)
            else:
                continue

            if not items:
                continue

            item = items[0]

            summary = summarize(item["text"], gemini_key)
            post_text = format_post(site, summary, item["url"], item)

            post_bluesky(
                bluesky_id,
                bluesky_pw,
                post_text,
                item["url"]
            )

            break  # 1サイトだけ投稿して終了

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

        # 1日1回想定 → 1件のみ
        item = new_items[0]

        summary = summarize(item["text"], gemini_key)
        post_text = format_post(site, summary, item["url"], item)

        if force_test:
            logging.info("[TEST MODE] " + post_text)
        else:
            post_bluesky(bluesky_id, bluesky_pw, post_text, item["url"])

        state[site_key].append(item["id"])

    save_state(state)


if __name__ == "__main__":
    main()

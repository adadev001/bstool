import os
import json
import yaml
import requests
import feedparser
import re
from datetime import datetime, timedelta
from atproto import Client, models

# =========================
# 環境変数
# =========================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
BLUESKY_HANDLE = os.getenv("BLUESKY_IDENTIFIER")
BLUESKY_PASSWORD = os.getenv("BLUESKY_PASSWORD")

STATE_FILE = "processed_urls.json"
SITES_FILE = "sites.yaml"


# =========================
# 状態管理
# =========================
def load_state():
    if not os.path.exists(STATE_FILE):
        return {}, True

    with open(STATE_FILE, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return {}, True

    if not data:
        return {}, True

    return data, False


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# =========================
# sites.yaml 読み込み
# =========================
def load_sites():
    with open(SITES_FILE, "r") as f:
        return yaml.safe_load(f)


# =========================
# RSS取得
# =========================
def fetch_rss(site_config):
    feed = feedparser.parse(site_config["url"])
    items = []

    for entry in feed.entries[: site_config.get("max_items", 50)]:
        items.append({
            "title": entry.get("title", ""),
            "description": entry.get("summary", ""),
            "url": entry.get("link")
        })

    return items


# =========================
# NVD API取得
# =========================
def fetch_nvd(site_config):
    threshold = site_config.get("cvss_threshold", 7.0)
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"

    params = {
        "pubStartDate": yesterday,
        "pubEndDate": now,
        "resultsPerPage": site_config.get("max_items", 50)
    }

    response = requests.get(base_url, params=params, timeout=30)
    response.raise_for_status()

    data = response.json()
    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            ""
        )

        metrics = cve.get("metrics", {})
        score = None

        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        if score and score >= threshold:
            results.append({
                "title": f"{cve_id} (CVSS {score})",
                "description": description,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })

    return results


# =========================
# HTML除去
# =========================
def clean_html(text):
    if not text:
        return ""
    text = re.sub('<.*?>', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


# =========================
# Gemini要約（英語→日本語対応）
# =========================
def summarize_with_gemini(text):
    if not text:
        return ""

    if not GEMINI_API_KEY:
        return text[:120]

    endpoint = f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"

    prompt = f"""
以下の記事内容を日本語で120文字以内に要約してください。
英語の場合は日本語に翻訳してから要約してください。

{text}
"""

    payload = {
        "contents": [{
            "parts": [{
                "text": prompt
            }]
        }]
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        result = data["candidates"][0]["content"]["parts"][0]["text"]
        return result.strip()
    except Exception:
        return text[:120]


# =========================
# 投稿整形（URLは必ず残す）
# =========================
def format_post(title, summary, url):
    title = title.strip()
    summary = summary.strip()
    url = url.strip()

    text_part = f"{title}\n{summary}"

    # 本文最大120文字固定（安全）
    if len(text_part) > 120:
        text_part = text_part[:117] + "..."

    return f"{text_part}\n{url}"


# =========================
# Bluesky投稿（facetリンク）
# =========================
def post_to_bluesky(text, url):
    if not BLUESKY_HANDLE or not BLUESKY_PASSWORD:
        print("Bluesky認証情報未設定")
        return

    client = Client()
    client.login(BLUESKY_HANDLE, BLUESKY_PASSWORD)

    start_char = text.find(url)
    if start_char == -1:
        client.send_post(text=text)
        print("URL位置検出失敗（facetなし投稿）")
        return

    end_char = start_char + len(url)

    start_byte = len(text[:start_char].encode("utf-8"))
    end_byte = len(text[:end_char].encode("utf-8"))

    facets = [
        models.AppBskyRichtextFacet.Main(
            index=models.AppBskyRichtextFacet.ByteSlice(
                byteStart=start_byte,
                byteEnd=end_byte,
            ),
            features=[
                models.AppBskyRichtextFacet.Link(uri=url)
            ],
        )
    ]

    client.send_post(text=text, facets=facets)
    print("Bluesky投稿成功（facetリンク）")


# =========================
# メイン処理
# =========================
def main():
    print("STATE_FILE exists:", os.path.exists(STATE_FILE))
    config = load_sites()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    processed_state, is_first_run = load_state()

    if not isinstance(processed_state, dict):
        processed_state = {}

    for site_id, site in sites.items():

        if not site.get("enabled", False):
            continue

        print(f"--- {site.get('display_name')} ---")

        site_urls = set(processed_state.get(site_id, []))

        try:
            if site["type"] == "rss":
                items = fetch_rss(site)
            elif site["type"] == "nvd_api":
                items = fetch_nvd(site)
            else:
                continue
        except Exception as e:
            print("取得エラー:", e)
            continue

        new_items = [i for i in items if i["url"] not in site_urls]

        if is_first_run and settings.get("skip_existing_on_first_run", True):
            print("初回のためスキップ")
            processed_state[site_id] = [i["url"] for i in items]
            continue

        if settings.get("force_test_mode", False) and items:
            print("強制テスト投稿モード")
            new_items = [items[0]]

        for item in new_items[:1]:
            cleaned = clean_html(item["description"])
            summary = summarize_with_gemini(cleaned)

            post_text = format_post(item["title"], summary, item["url"])

            print("POST TEXT:\n", post_text)
            print("URL:", item["url"])

            post_to_bluesky(post_text, item["url"])
            site_urls.add(item["url"])

        if not new_items:
            print("新着なし")

        processed_state[site_id] = list(site_urls)

    save_state(processed_state)


if __name__ == "__main__":
    main()

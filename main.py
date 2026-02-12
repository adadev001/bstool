import os
import json
import yaml
import requests
import feedparser
from datetime import datetime, timedelta
from atproto import Client

# =========================
# 環境変数
# =========================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
BLUESKY_HANDLE = os.getenv("BLUESKY_IDENTIFIER")
BLUESKY_PASSWORD = os.getenv("BLUESKY_PASSWORD")

STATE_FILE = "processed_urls.json"
SITES_FILE = "sites.yaml"


# =========================
# 状態管理（辞書型）
# =========================
def load_state():
    if not os.path.exists(STATE_FILE):
        return {}, True
    with open(STATE_FILE, "r") as f:
        return json.load(f), False


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
# Gemini要約
# =========================
def summarize_with_gemini(text):
    if not GEMINI_API_KEY:
        return text[:120]

    endpoint = f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"

    payload = {
        "contents": [{
            "parts": [{
                "text": f"次の内容を日本語で120文字以内で要約してください:\n{text}"
            }]
        }]
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return text[:120]


# =========================
# 投稿整形（140文字）
# =========================
def format_post(title, summary, url):
    post = f"{title}\n{summary}\n{url}"
    if len(post) > 140:
        allowed = 140 - len(title) - len(url) - 5
        if allowed < 0:
            allowed = 0
        summary = summary[:allowed] + "..."
        post = f"{title}\n{summary}\n{url}"
    return post


# =========================
# Bluesky投稿
# =========================
def post_to_bluesky(text):
    if not BLUESKY_HANDLE or not BLUESKY_PASSWORD:
        print("Bluesky認証情報未設定")
        return

    client = Client()
    client.login(BLUESKY_HANDLE, BLUESKY_PASSWORD)
    client.send_post(text)
    print("Bluesky投稿成功")


# =========================
# メイン（辞書型state対応）
# =========================
def main():
    config = load_sites()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    processed_state, is_first_run = load_state()

    # 念のためdict保証
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

        # 初回スキップ
        if is_first_run and settings.get("skip_existing_on_first_run", True):
            print("初回のためスキップ")
            processed_state[site_id] = [i["url"] for i in items]
            continue

        # 投稿（最大1件）
        for item in new_items[:1]:
            summary = summarize_with_gemini(item["description"])
            post_text = format_post(item["title"], summary, item["url"])
            post_to_bluesky(post_text)
            site_urls.add(item["url"])

        if not new_items:
            print("新着なし")

        processed_state[site_id] = list(site_urls)

    save_state(processed_state)


if __name__ == "__main__":
    main()

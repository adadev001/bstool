import os
import json
import requests
from datetime import datetime, timedelta
from atproto import Client

# ========= 設定 =========
STATE_FILE = "processed_urls.json"
CVSS_THRESHOLD = 7.0
MAX_POST_ITEMS = 1  # 1日1回想定

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
BLUESKY_HANDLE = os.getenv("BLUESKY_HANDLE")
BLUESKY_PASSWORD = os.getenv("BLUESKY_PASSWORD")

# ========= 状態管理 =========
def load_state():
    if not os.path.exists(STATE_FILE):
        return set(), True  # 初回
    with open(STATE_FILE, "r") as f:
        return set(json.load(f)), False

def save_state(urls):
    with open(STATE_FILE, "w") as f:
        json.dump(list(urls), f, indent=2)

# ========= NVD API =========
def fetch_nvd_recent():
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"

    params = {
        "pubStartDate": yesterday,
        "pubEndDate": now,
        "resultsPerPage": 50
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

        if score and score >= CVSS_THRESHOLD:
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            results.append({
                "id": cve_id,
                "description": description,
                "score": score,
                "url": url
            })

    return sorted(results, key=lambda x: x["score"], reverse=True)

# ========= Gemini要約 =========
def summarize_with_gemini(text):
    if not GEMINI_API_KEY:
        print("GEMINI_API_KEY未設定")
        return text[:100]

    endpoint = f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"

    payload = {
        "contents": [{
            "parts": [{
                "text": f"次の脆弱性情報を日本語で簡潔に要約してください:\n{text}"
            }]
        }]
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        print("Gemini要約失敗:", e)
        return text[:100]

# ========= 投稿整形（140文字） =========
def format_post(title, summary, url):
    post = f"{title}\n{summary}\n{url}"
    if len(post) > 140:
        allowed = 140 - len(title) - len(url) - 5
        summary = summary[:allowed] + "..."
        post = f"{title}\n{summary}\n{url}"
    return post

# ========= Bluesky投稿 =========
def post_to_bluesky(text):
    if not BLUESKY_HANDLE or not BLUESKY_PASSWORD:
        print("Bluesky認証情報未設定")
        return

    client = Client()
    client.login(BLUESKY_HANDLE, BLUESKY_PASSWORD)
    client.send_post(text)
    print("Bluesky投稿成功")

# ========= メイン =========
def main():
    print("=== Secure NVD Bot ===")

    processed_urls, is_first_run = load_state()

    try:
        vulns = fetch_nvd_recent()
    except Exception as e:
        print("NVD取得エラー:", e)
        return

    new_items = [v for v in vulns if v["url"] not in processed_urls]

    if is_first_run:
        print("初回実行のため既存記事をスキップします")
        save_state([v["url"] for v in vulns])
        return

    if not new_items:
        print("新着なし")
        return

    for item in new_items[:MAX_POST_ITEMS]:
        summary = summarize_with_gemini(item["description"])
        post_text = format_post(
            f"{item['id']} (CVSS {item['score']})",
            summary,
            item["url"]
        )
        post_to_bluesky(post_text)
        processed_urls.add(item["url"])

    save_state(processed_urls)

    print("=== end ===")


if __name__ == "__main__":
    main()

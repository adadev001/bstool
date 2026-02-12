import os
import json
import requests
import feedparser
import time

# ========= 設定 =========
DRY_RUN = True  # 本番時は False
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

SITES = {
    "thehackernews": {
        "url": "https://feeds.feedburner.com/TheHackersNews"
    },
    "securitynext": {
        "url": "https://www.security-next.com/feed"
    }
}

STATE_FILE = "processed.json"


# ========= 状態管理 =========
def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ========= Gemini 要約 =========
def summarize_with_gemini(text, retries=3):

    if not GEMINI_API_KEY:
        print("GEMINI_API_KEY未設定")
        return "要約失敗"

    endpoint = (
        f"https://generativelanguage.googleapis.com/v1/"
        f"models/gemini-2.5-flash-lite:generateContent?key={GEMINI_API_KEY}"
    )

    prompt = f"120字以内で要点を簡潔にまとめてください。\n{text}"

    data = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 160
        }
    }

    headers = {"Content-Type": "application/json"}

    for attempt in range(retries):
        try:
            response = requests.post(endpoint, headers=headers, json=data, timeout=20)
            response.raise_for_status()
            result = response.json()

            summary = (
                result.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            ).strip()

            return summary if summary else "要約失敗"

        except requests.exceptions.RequestException as e:
            print(f"Geminiエラー（{attempt+1}/{retries}）:", e)

            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                return "要約失敗"


# ========= RSS処理 =========
def process_rss(site_name, site_config, state):
    print(f"[{site_name}] 処理開始")

    feed = feedparser.parse(site_config["url"])
    entries = feed.entries

    if site_name not in state:
        state[site_name] = {"urls": []}

    site_state = state[site_name]
    new_entries = []

    for entry in entries:
        if entry.link not in site_state["urls"]:
            new_entries.append(entry)

    if not new_entries:
        print(f"[{site_name}] 新着なし")
        return

    entry = new_entries[0]

    print(f"[{site_name}] 新着: {entry.title}")

    # ★ RSSのtitle + summaryのみ使用（本文取得しない）
    rss_text = f"{entry.title} {entry.summary}"

    summary = summarize_with_gemini(rss_text)

    # ▼ URL込み120字制御
    url = entry.link
    max_total = 120
    available = max_total - len(url) - 1

    if available < 10:
        summary = "詳細はリンク参照"
    else:
        if len(summary) > available:
            summary = summary[:available - 3] + "..."

    post_text = f"{summary}\n{url}"

    print("[DRY RUN] 投稿内容:")
    print(post_text)

    if not DRY_RUN:
        # Bluesky投稿処理を書く
        pass

    site_state["urls"].append(entry.link)


# ========= メイン =========
def main():
    print("=== main.py start ===")

    state = load_state()

    for site_name, site_config in SITES.items():
        process_rss(site_name, site_config, state)

    save_state(state)

    print("=== main.py end ===")


if __name__ == "__main__":
    main()

import os
import json
import requests
import feedparser
from bs4 import BeautifulSoup

# ========= 設定 =========
DRY_RUN = True  # 本番時は False

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

SITES = {
    "thehackernews": {
        "type": "rss",
        "url": "https://feeds.feedburner.com/TheHackersNews"
    },
    "securitynext": {
        "type": "rss",
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


# ========= 本文取得 =========
def fetch_article_text(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        paragraphs = soup.find_all("p")
        text = " ".join(p.get_text() for p in paragraphs)

        # 無料最適化（改行除去 + 800文字制限）
        text = text.replace("\n", " ").strip()[:800]

        return text
    except Exception as e:
        print("本文取得エラー:", e)
        return ""


# ========= Gemini 要約 =========
def summarize_with_gemini(text):
    endpoint = (
        f"https://generativelanguage.googleapis.com/v1/"
        f"models/gemini-2.5-flash-lite:generateContent?key={GEMINI_API_KEY}"
    )

    prompt = f"次を140字以内で日本語要約:\n{text}"

    headers = {"Content-Type": "application/json"}

    data = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ]
    }

    try:
        response = requests.post(endpoint, headers=headers, json=data, timeout=20)
        response.raise_for_status()
        result = response.json()

        summary = result["candidates"][0]["content"]["parts"][0]["text"]
        return summary.strip()

    except Exception as e:
        print("Geminiエラー:", e)
        return "要約に失敗しました"


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

    # テストモード（まだ戻さない）
    if not new_entries and entries:
        print(f"[{site_name}] テストモード：先頭記事を強制処理")
        new_entries = [entries[0]]

    if not new_entries:
        print(f"[{site_name}] 新着なし")
        return

    # 1件だけ処理
    entry = new_entries[0]

    print(f"[{site_name}] 新着: {entry.title}")

    article_text = fetch_article_text(entry.link)

    if not article_text:
        print("本文なし")
        return

    print("---- 本文先頭800文字 ----")
    print(article_text)
    print("------------------------")

    summary = summarize_with_gemini(article_text)

    # 140字制御（リンク込み）
    max_length = 140 - len(entry.link) - 1

    if len(summary) > max_length:
        summary = summary[:max_length - 3] + "..."

    post_text = f"{summary}\n{entry.link}"

    print("[DRY RUN] 投稿内容:")
    print(post_text)

    # 本番投稿
    if not DRY_RUN:
        # ここにBluesky投稿処理を書く
        pass

    # 処理済み保存
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

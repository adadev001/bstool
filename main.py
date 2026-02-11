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
def fetch_article_text(url, title):
    """
    ▼ 最適化ポイント
    - 改行除去
    - 連続空白圧縮
    - タイトルを先頭に追加（要点把握効率UP）
    - 全体600文字に制限（無料枠節約）
    """

    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        paragraphs = soup.find_all("p")
        text = " ".join(p.get_text() for p in paragraphs)

        # 改行削除＋空白圧縮
        text = text.replace("\n", " ").replace("  ", " ").strip()

        # タイトル追加
        text = f"{title} {text}"

        # 600文字制限
        text = text[:600]

        return text

    except Exception as e:
        print("本文取得エラー:", e)
        return ""


# ========= Gemini 要約 =========
def summarize_with_gemini(text):
    """
    ▼ 最適化ポイント
    - prompt短文化
    - 120字以内指定（出力トークン削減）
    - temperature=0.2（安定＆無駄出力防止）
    - maxOutputTokens=200（安全上限）
    """

    endpoint = (
        f"https://generativelanguage.googleapis.com/v1/"
        f"models/gemini-2.5-flash-lite:generateContent?key={GEMINI_API_KEY}"
    )

    # プロンプト短文化
    prompt = f"120字以内で日本語要約:\n{text}"

    data = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 200
        }
    }

    headers = {"Content-Type": "application/json"}

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

    # テストモード維持
    if not new_entries and entries:
        print(f"[{site_name}] テストモード：先頭記事を強制処理")
        new_entries = [entries[0]]

    if not new_entries:
        print(f"[{site_name}] 新着なし")
        return

    entry = new_entries[0]

    print(f"[{site_name}] 新着: {entry.title}")

    article_text = fetch_article_text(entry.link, entry.title)

    if not article_text:
        print("本文なし")
        return

    print("---- 本文先頭600文字 ----")
    print(article_text)
    print("------------------------")

    summary = summarize_with_gemini(article_text)

    # ▼ 120字＋リンク込みで安全制御
    max_length = 120
    if len(summary) > max_length:
        summary = summary[:max_length - 3] + "..."

    post_text = f"{summary}\n{entry.link}"

    print("[DRY RUN] 投稿内容:")
    print(post_text)

    # 本番投稿
    if not DRY_RUN:
        # Bluesky投稿処理を書く
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

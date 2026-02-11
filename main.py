import os
import json
import feedparser
import yaml
import requests
from bs4 import BeautifulSoup

from bluesky_client import BlueskyClient

# ==============================
# 設定
# ==============================

SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"

DRY_RUN = True  # 本番は False

bluesky = BlueskyClient(dry_run=DRY_RUN)

# ==============================
# state 読み込み
# ==============================

def load_processed():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def save_processed(data):
    with open(STATE_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ==============================
# 本文取得
# ==============================

def extract_article_text(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"本文取得失敗: {url} ({e})")
        return ""

    soup = BeautifulSoup(response.text, "html.parser")

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    paragraphs = soup.find_all("p")
    text = "\n".join(p.get_text().strip() for p in paragraphs)

    return text.strip()

# ==============================
# Gemini 要約
# ==============================

def summarize_with_gemini(text, max_output_chars=140):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("GEMINI_API_KEY未設定")
        return None

    endpoint = f"https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key={api_key}"

    prompt = f"""
以下の記事を日本語で{max_output_chars}文字以内に要約してください。
専門用語は可能な限り維持してください。
簡潔にまとめてください。

{text}
"""

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        summary = result["candidates"][0]["content"]["parts"][0]["text"].strip()
        return summary
    except Exception as e:
        print("Gemini要約失敗:", e)
        return None

# ==============================
# RSS処理
# ==============================

def process_rss(site_name, site_config, processed_data):
    print(f"[{site_name}] 処理開始 (type=rss)")

    feed = feedparser.parse(site_config["url"])
    entries = feed.entries

    site_state = processed_data.get(site_name, {
        "initialized": False,
        "urls": []
    })

    # 初回
    if not site_state["initialized"]:
        print(f"[{site_name}] 初回実行：既存記事をスキップ")
        site_state["urls"] = [entry.link for entry in entries]
        site_state["initialized"] = True
        processed_data[site_name] = site_state
        print(f"[{site_name}] 初期化完了（記録URL数: {len(site_state['urls'])}）")
        return

    # 通常
    new_entries = []

    for entry in entries:
        if entry.link not in site_state["urls"]:
            new_entries.append(entry)

    # ★ テスト用：新着が無い場合は先頭記事を1件だけ使う
    if not new_entries and entries:
        print(f"[{site_name}] テストモード：先頭記事を強制処理")
        new_entries = [entries[0]]

    # ★ 最大1件に制限
    if new_entries:
        new_entries = new_entries[:1]

    if not new_entries:
        print(f"[{site_name}] 新着なし")
        return

    new_entries.reverse()

    for entry in new_entries:
        print(f"[{site_name}] 新着: {entry.title}")

        article_text = extract_article_text(entry.link)
        if not article_text:
            print("本文取得失敗または空本文")
            continue

        ai_input_text = article_text[:1200]

        print("---- 本文先頭1200文字 ----")
        print(ai_input_text)
        print("------------------------")

        summary = summarize_with_gemini(ai_input_text)

        if summary:
            if len(summary) > 140:
                summary = summary[:137] + "..."
            post_text = f"{summary}\n{entry.link}"
        else:
            print("AI失敗のためタイトル投稿へフォールバック")
            post_text = f"{entry.title}\n{entry.link}"

        if DRY_RUN:
            print("[DRY RUN] 投稿内容:")
            print(post_text)
        else:
            bluesky.post(post_text)

        site_state["urls"].append(entry.link)

    processed_data[site_name] = site_state

# ==============================
# main
# ==============================

def main():
    print("=== main.py start ===")

    with open(SITES_FILE, "r") as f:
        config = yaml.safe_load(f)

    sites = config["sites"]
    processed_data = load_processed()

    for site_name, site_config in sites.items():

        if not site_config.get("enabled", True):
            print(f"[{site_name}] 無効化されているためスキップ")
            continue

        if site_config["type"] == "rss":
            process_rss(site_name, site_config, processed_data)

    save_processed(processed_data)

    print("=== main.py end ===")

if __name__ == "__main__":
    main()

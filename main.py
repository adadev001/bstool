import os
import json
import re
import feedparser
import requests
from google import genai
from google.genai import types

STATE_FILE = "processed_urls.json"
SITES_FILE = "sites.yaml"
MODEL_NAME = "gemini-2.5-flash-lite"  # ★ 固定

# -----------------------------
# HTMLタグ除去
# -----------------------------
def clean_html(text):
    return re.sub('<.*?>', '', text or "")

# -----------------------------
# 状態読み込み
# -----------------------------
def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

# -----------------------------
# 状態保存
# -----------------------------
def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

# -----------------------------
# Gemini 要約（英語なら翻訳→要約）
# -----------------------------
def summarize_text(text):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY が設定されていません")

    client = genai.Client(api_key=api_key)

    prompt = f"""
あなたはITニュース専門の編集者です。

以下の文章を処理してください。

1. 英語の場合は必ず自然な日本語に翻訳する
2. その内容を140文字以内で要約する
3. 出力は要約本文のみ

本文:
{text}
"""

    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.3,
        ),
    )

    return response.text.strip()

# -----------------------------
# 140文字整形
# -----------------------------
def format_post(summary, url):
    base = f"{summary}\n{url}"
    if len(base) <= 140:
        return base

    allowed = 140 - len(url) - 1
    trimmed = summary[:allowed - 3] + "..."
    return f"{trimmed}\n{url}"

# -----------------------------
# Bluesky投稿
# -----------------------------
def post_to_bluesky(text):
    from atproto import Client

    identifier = os.getenv("BLUESKY_IDENTIFIER")
    password = os.getenv("BLUESKY_PASSWORD")

    if not identifier or not password:
        raise ValueError("Blueskyの認証情報が未設定です")

    client = Client()
    client.login(identifier, password)
    client.send_post(text=text)

# -----------------------------
# メイン処理
# -----------------------------
def main():
    import yaml

    state = load_state()

    with open(SITES_FILE, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    sites = config.get("sites", [])

    for site in sites:
        site_name = site["name"]
        feed_url = site["url"]

        if site_name not in state:
            state[site_name] = []

        feed = feedparser.parse(feed_url)

        for entry in feed.entries:
            url = entry.link

            if url in state[site_name]:
                continue

            print(f"New article: {entry.title}")

            summary_source = clean_html(entry.get("summary", entry.title))

            try:
                summary = summarize_text(summary_source)
                post_text = format_post(summary, url)
                post_to_bluesky(post_text)
                print("Posted to Bluesky")

                state[site_name].append(url)

            except Exception as e:
                print("Error:", e)

    save_state(state)


if __name__ == "__main__":
    main()

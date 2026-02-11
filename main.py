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

# テスト時は True、本番は False
DRY_RUN = True

bluesky = BlueskyClient(dry_run=DRY_RUN)

# ==============================
# state 読み込み
# ==============================

def load_processed():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)

# ==============================
# state 保存
# ==============================

def save_processed(data):
    with open(STATE_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ==============================
# 本文取得（AI用）
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
# 投稿フォーマット（140文字制限）
# ==============================

def format_post(title, url, max_length=140):
    base_text = f"{title}\n{url}"

    if len(base_text) <= max_length:
        return base_text

    url_part = f"\n{url}"
    available_length = max_length - len(url_part) - 3

    shortened_title = title[:available_length] + "..."

    return f"{shortened_title}{url_part}"

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

    # --------------------------
    # 初回実行
    # --------------------------
    if not site_state["initialized"]:
        print(f"[{site_name}] 初回実行：既存記事をスキップ")

        site_state["urls"] = [entry.link for entry in entries]
        site_state["initialized"] = True

        processed_data[site_name] = site_state
        print(f"[{site_name}] 初期化完了（記録URL数: {len(site_state['urls'])}）")
        return

    # --------------------------
    # 通常実行
    # --------------------------
    new_entries = []

    for entry in entries:
        # 強制テストは以下のif~append(entry)の2行をコメントアウトして
        new_entries.append(entry)の行のコメントを外す
        if entry.link not in site_state["urls"]:
            new_entries.append(entry)

        #new_entries.append(entry)

    if not new_entries:
        print(f"[{site_name}] 新着なし")
        return

    new_entries.reverse()

    for entry in new_entries:
        print(f"[{site_name}] 新着: {entry.title}")

        # 本文取得（AI材料）
        article_text = extract_article_text(entry.link)

        if not article_text:
            print("本文取得失敗または空本文")
            continue

        # 1200文字抽出
        ai_input_text = article_text[:1200]

        print("---- 本文先頭1200文字 ----")
        print(ai_input_text)
        print("------------------------")

        # 現在はタイトル投稿（次フェーズでAI要約に置換）
        post_text = format_post(entry.title, entry.link, max_length=140)

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

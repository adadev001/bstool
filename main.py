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

DRY_RUN = False

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
        if entry.link not in site_state["urls"]:
            new_entries.append(entry)

    if not new_entries:
        print(f"[{site_name}] 新着なし")
        return

    new_entries.reverse()

    for entry in new_entries:
        print(f"[{site_name}] 新着: {entry.title}")
        print(f"[{site_name}] 本文取得中: {entry.link}")

        article_text = extract_article_text(entry.link)

        print("---- 本文先頭300文字 ----")
        print(article_text[:300])
        print("------------------------")

        # 🔴 まだ投稿しない（確認フェーズ）
        # post_text = f"{entry.title}\n{entry.link}"
        # bluesky.post(post_text)

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

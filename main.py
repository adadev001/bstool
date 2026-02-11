import os
import json
import feedparser
import yaml

from bluesky_client import BlueskyClient

# ==============================
# 設定
# ==============================

SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"

# 最初は必ず True にする（事故防止）
DRY_RUN = False

# Blueskyクライアント初期化
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
# RSS処理
# ==============================

def process_rss(site_name, site_config, processed_data):
    print(f"[{site_name}] 処理開始 (type=rss)")

    feed = feedparser.parse(site_config["url"])
    entries = feed.entries

    # サイトごとの記録を取得
    site_state = processed_data.get(site_name, {
        "initialized": False,
        "urls": []
    })

    # --------------------------
    # 初回実行処理
    # --------------------------
    if not site_state["initialized"]:
        print(f"[{site_name}] 初回実行：既存記事をスキップ")

        site_state["urls"] = [entry.link for entry in entries]
        site_state["initialized"] = True

        processed_data[site_name] = site_state
        print(f"[{site_name}] 初期化完了（記録URL数: {len(site_state['urls'])}）")
        return

    # --------------------------
    # 通常実行（新着判定）
    # --------------------------
    new_entries = []

    for entry in entries:
        if entry.link not in site_state["urls"]:
            new_entries.append(entry)

    if not new_entries:
        print(f"[{site_name}] 新着なし")
        return

    # 古い順に投稿したいので reverse
    new_entries.reverse()

    for entry in new_entries:
        print(f"[{site_name}] 新着: {entry.title}")

        # 投稿内容作成
        post_text = f"{entry.title}\n{entry.link}"

        # Bluesky投稿
        bluesky.post(post_text)

        # state更新
        site_state["urls"].append(entry.link)

    processed_data[site_name] = site_state


# ==============================
# main
# ==============================

def main():
    print("=== main.py start ===")

    # 設定読み込み
    with open(SITES_FILE, "r") as f:
        config = yaml.safe_load(f)

    sites = config["sites"]

    # state読み込み
    processed_data = load_processed()

    # サイトごとに処理
    for site_name, site_config in sites.items():

        # 無効サイトはスキップ
        if not site_config.get("enabled", True):
            print(f"[{site_name}] 無効化されているためスキップ")
            continue

        if site_config["type"] == "rss":
            process_rss(site_name, site_config, processed_data)

    # state保存
    save_processed(processed_data)

    print("=== main.py end ===")


if __name__ == "__main__":
    main()

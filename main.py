import os
import json
import yaml
import feedparser

# ---------------------------------------------
# ファイル定義
# ---------------------------------------------
SITES_FILE = "sites.yaml"
PROCESSED_FILE = "processed_urls.json"


# ---------------------------------------------
# 設定・状態読み込み
# ---------------------------------------------
def load_config():
    if not os.path.exists(SITES_FILE):
        raise FileNotFoundError(f"{SITES_FILE} が見つかりません")

    with open(SITES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_processed():
    """
    処理済みURL情報を読み込む
    初回実行・空ファイル・破損時は空dictを返す
    """
    if not os.path.exists(PROCESSED_FILE):
        return {}

    try:
        with open(PROCESSED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def save_processed(data):
    """
    処理結果を保存する
    """
    with open(PROCESSED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ---------------------------------------------
# RSS処理（TypeA）
# ---------------------------------------------
def process_rss(site, processed, skip_existing):
    name = site["name"]
    feed_url = site["url"]
    max_items = site.get("max_items", 200)

    # サイト単位の初期化（site.yaml追加時に自動対応）
    if name not in processed:
        processed[name] = {
            "initialized": False,
            "urls": []
        }

    site_data = processed[name]
    known_urls = set(site_data.get("urls", []))

    feed = feedparser.parse(feed_url)

    # -----------------------------
    # 初回実行
    # -----------------------------
    if not site_data.get("initialized", False):
        if skip_existing:
            print(f"[{name}] 初回実行：既存記事をスキップ")
            for entry in feed.entries:
                if "link" in entry:
                    known_urls.add(entry.link)

        # ★ ここで「初回完了」を確定させる
        site_data["initialized"] = True
        site_data["urls"] = list(known_urls)[:max_items]

        print(f"[{name}] 初期化完了（記録URL数: {len(site_data['urls'])}）")
        return

    # -----------------------------
    # 2回目以降（新着のみ）
    # -----------------------------
    new_count = 0
    for entry in feed.entries:
        if "link" not in entry:
            continue

        if entry.link in known_urls:
            continue

        print(f"[{name}] 新着: {entry.title}")
        known_urls.add(entry.link)
        new_count += 1

    if new_count == 0:
        print(f"[{name}] 新着なし")

    site_data["urls"] = list(known_urls)[:max_items]



# ---------------------------------------------
# メイン処理
# ---------------------------------------------
def main():
    print("=== main.py start ===")

    config = load_config()

    settings = config.get("settings", {})
    sites = config.get("sites", [])

    if not sites:
        print("⚠ sites.yaml に sites が定義されていません")
        return

    skip_existing = settings.get("skip_existing_on_first_run", True)

    processed = load_processed()

    for site in sites:
        if not site.get("enabled", True):
            continue

        site_type = site.get("type", "rss")

        print(f"[{site['name']}] 処理開始 (type={site_type})")

        if site_type == "rss":
            process_rss(site, processed, skip_existing)
        else:
            print(f"[WARN] 未対応の type: {site_type}")

    save_processed(processed)
    print("=== main.py end ===")


if __name__ == "__main__":
    main()

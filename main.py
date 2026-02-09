import os
import json
import yaml
import feedparser

# 処理済みURLを保存するファイル
PROCESSED_FILE = "processed_urls.json"
SITES_FILE = "sites.yaml"


def load_sites():
    """
    sites.yaml を読み込む
    """
    with open(SITES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_processed_urls():
    """
    processed_urls.json を読み込む
    - ファイルが無い or 空の場合は空のdictを返す
    """
    if not os.path.exists(PROCESSED_FILE):
        return {}

    try:
        with open(PROCESSED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        # 中身が壊れている／空の場合の保険
        return {}


def save_processed_urls(data):
    """
    処理済みURL情報を JSON に保存する
    Artifact方式では「このファイルを書き出す」ことが最重要
    """
    with open(PROCESSED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def process_rss(site, processed_data):
    """
    RSSサイトを処理する（TypeA）
    """
    site_name = site["name"]
    rss_url = site["rss"]

    # サイト単位の初期データを自動生成
    if site_name not in processed_data:
        processed_data[site_name] = {
            "initialized": False,
            "urls": []
        }

    site_data = processed_data[site_name]
    processed_urls = set(site_data["urls"])

    feed = feedparser.parse(rss_url)

    new_urls = []

    # 初回実行時は既存記事をすべてスキップ
    if not site_data["initialized"]:
        print(f"[{site_name}] 初回実行：既存記事をスキップ")

        for entry in feed.entries:
            if "link" in entry:
                processed_urls.add(entry.link)

        site_data["initialized"] = True

    else:
        # 2回目以降：新着記事のみ処理
        for entry in feed.entries:
            if "link" not in entry:
                continue

            if entry.link in processed_urls:
                continue

            print(f"[{site_name}] 新着: {entry.title}")
            new_urls.append(entry.link)
            processed_urls.add(entry.link)

    # 更新結果を保存用データに反映
    site_data["urls"] = list(processed_urls)

    return new_urls


def main():
    sites = load_sites()
    processed_data = load_processed_urls()

    for site in sites["sites"]:
        if site.get("type") != "rss":
            continue

        process_rss(site, processed_data)

    # ★ 最重要ポイント ★
    # 実行結果を必ず JSON に保存する
    save_processed_urls(processed_data)


if __name__ == "__main__":
    main()

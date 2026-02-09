import feedparser
import yaml
import json
import os
import logging

PROCESSED_FILE = "processed_urls.json"


# -------------------------------------------------
# ログ設定
# -------------------------------------------------
def setup_logger(level: str):
    """
    ログレベルを設定する。
    INFO : 通常運用向け
    DEBUG: トラブルシュート向け
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )


# -------------------------------------------------
# sites.yaml 読み込み
# -------------------------------------------------
def load_sites():
    """
    サイト定義ファイルを読み込む
    """
    with open("sites.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# -------------------------------------------------
# processed_urls.json 読み込み
# -------------------------------------------------
def load_processed_urls():
    """
    処理済みURLの状態ファイルを読み込む。
    ファイルが無い、または空の場合は空dictを返す。
    """
    if not os.path.exists(PROCESSED_FILE):
        return {}

    if os.path.getsize(PROCESSED_FILE) == 0:
        return {}

    with open(PROCESSED_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


# -------------------------------------------------
# site.yaml と JSON の構造同期
# -------------------------------------------------
def sync_processed_structure(processed, sites):
    """
    site.yaml を正として processed_urls.json を補完する。
    - サイト追加時は自動初期化
    - 既存JSONとの後方互換を保つ
    """
    for site in sites:
        name = site["name"]

        if name not in processed:
            processed[name] = {
                "initialized": False,
                "urls": []
            }
        else:
            processed[name].setdefault("initialized", False)
            processed[name].setdefault("urls", [])


# -------------------------------------------------
# processed_urls.json 保存
# -------------------------------------------------
def save_processed_urls(processed, sites):
    """
    処理済みURLを保存する。
    max_items が指定されている場合は古いURLを削除する。
    """
    for site in sites:
        name = site["name"]
        max_items = site.get("max_items")

        if max_items and name in processed:
            processed[name]["urls"] = processed[name]["urls"][-max_items:]

    with open(PROCESSED_FILE, "w", encoding="utf-8") as f:
        json.dump(processed, f, indent=2, ensure_ascii=False)


# -------------------------------------------------
# RSS処理
# -------------------------------------------------
def process_rss(site, processed, skip_existing_on_first_run):
    """
    RSSを取得し、新着記事のみ返す。
    type が未指定の場合のデフォルト処理。
    """
    feed = feedparser.parse(site["url"])
    site_name = site["name"]
    site_data = processed[site_name]

    # 初回実行時は既存記事を保存のみして終了
    if not site_data["initialized"] and skip_existing_on_first_run:
        logging.info(f"[{site_name}] 初回実行：既存記事をスキップ")
        for entry in feed.entries:
            if hasattr(entry, "link"):
                site_data["urls"].append(entry.link)

        site_data["initialized"] = True
        return []

    new_entries = []

    for entry in feed.entries:
        if not hasattr(entry, "link"):
            continue

        if entry.link not in site_data["urls"]:
            new_entries.append(entry)

    return new_entries


# -------------------------------------------------
# メイン処理
# -------------------------------------------------
def main():
    config = load_sites()

    settings = config.get("settings", {})
    sites = config["sites"]

    setup_logger(settings.get("log_level", "INFO"))

    processed = load_processed_urls()

    # site.yaml を基準に JSON を自動補完
    sync_processed_structure(processed, sites)

    skip_existing = settings.get("skip_existing_on_first_run", False)

    for site in sites:
        if not site.get("enabled", True):
            continue

        # type 未指定時は rss とみなす（TypeA）
        site_type = site.get("type", "rss")

        if site_type == "rss":
            new_entries = process_rss(site, processed, skip_existing)

            for entry in new_entries:
                logging.info(f"[NEW] {site['display_name']} - {entry.title}")
                logging.info(f"      {entry.link}")

                # TODO:
                # 1. 言語判定
                # 2. Gemini 翻訳
                # 3. Gemini 要約
                # 4. Bluesky 投稿
                # 投稿成功後にのみURL保存する想定

                processed[site["name"]]["urls"].append(entry.link)

            processed[site["name"]]["initialized"] = True

        else:
            logging.warning(f"未対応の type: {site_type}")

    save_processed_urls(processed, sites)


if __name__ == "__main__":
    main()

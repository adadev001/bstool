def process_rss(site, processed, skip_existing):
    name = site["name"]
    feed_url = site["url"]          # ← ここがポイント
    max_items = site.get("max_items", 200)

    if name not in processed:
        processed[name] = {
            "initialized": False,
            "urls": []
        }

    site_data = processed[name]
    known_urls = set(site_data["urls"])

    feed = feedparser.parse(feed_url)

    if not site_data["initialized"]:
        if skip_existing:
            print(f"[{name}] 初回実行：既存記事をスキップ")
            for entry in feed.entries:
                if "link" in entry:
                    known_urls.add(entry.link)

        site_data["initialized"] = True
        site_data["urls"] = list(known_urls)[:max_items]
        return

    for entry in feed.entries:
        if "link" not in entry:
            continue
        if entry.link in known_urls:
            continue

        print(f"[{name}] 新着: {entry.title}")
        known_urls.add(entry.link)

    site_data["urls"] = list(known_urls)[:max_items]

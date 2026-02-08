import feedparser

RSS_URL = "https://feeds.feedburner.com/TheHackersNews"

def main():
    feed = feedparser.parse(RSS_URL)

    print(f"feed title: {feed.feed.get('title')}")

    print("latest entries:")
    for entry in feed.entries[:5]:
        print("-")
        print("title:", entry.get("title"))
        print("link:", entry.get("link"))

if __name__ == "__main__":
    main()

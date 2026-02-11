import feedparser
import requests
from bs4 import BeautifulSoup


def fetch_rss_items(site_config):
    url = site_config["url"]
    max_items = site_config.get("max_items", 50)

    feed = feedparser.parse(url)
    items = []

    for entry in feed.entries[:max_items]:
        item = {
            "title": entry.get("title", ""),
            "link": entry.get("link", ""),
        }
        items.append(item)

    return items


def extract_article_text(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"本文取得失敗: {url} ({e})")
        return ""

    soup = BeautifulSoup(response.text, "html.parser")

    # script / style 削除
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    paragraphs = soup.find_all("p")
    text = "\n".join(p.get_text().strip() for p in paragraphs)

    return text.strip()
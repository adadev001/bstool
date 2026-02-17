import os
import json
import requests
import yaml
import feedparser
import logging
import time
import random
from google import genai
from atproto import Client, models

# ==========================
# 定数
# ==========================

SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"
MAX_POST_LENGTH = 140


# ==========================
# 設定読み込み
# ==========================

def load_config():
    with open(SITES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except:
            return {}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def cvss_to_severity(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def format_post(site, summary, url, item):
    body = summary.replace("\n", " ").strip()

    if site["type"] == "nvd_api":
        cve_id = item["id"]
        score = item.get("score", 0)
        severity = cvss_to_severity(score)

        header = f"{cve_id}"
        score_line = f"CVSS {score} | {severity}"

        base_text = f"{header}\n{score_line}\n\n{body}"
    else:
        base_text = body

    if len(base_text) > MAX_POST_LENGTH:
        base_text = base_text[:MAX_POST_LENGTH - 2] + "…"

    return base_text


# ==========================
# 本文処理の最適カット（flash-lite 前提）
# ==========================

def body_trim(text, max_length=2500):
    """
    Gemini flash-lite 向けに本文を最適化する前処理。

    目的:
    - 要約品質が急落する「入力過多」を防ぐ
    - 記事構造を保ったまま、要約に必要な部分だけ渡す

    ルール:
    - 見出し
    - リード文
    - 本文冒頭 1〜2 段落
    - 全体で最大 2,000〜2,500 文字（超えたら truncate）
    """

    if not text:
        return ""

    # 改行を正規化
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")

    # 段落単位で分割（空行区切り）
    paragraphs = [
        p.strip()
        for p in normalized.split("\n\n")
        if p.strip()
    ]

    picked = []

    # ① 見出し（最初の行）
    # RSS / NVD どちらも先頭にタイトルが来る前提
    if paragraphs:
        picked.append(paragraphs[0])

    # ② リード文 + 本文冒頭 1〜2 段落
    # 情報密度が高いのは最初の数段落のみ
    for p in paragraphs[1:]:
        # 明らかなノイズ段落を除外
        if len(p) < 40:
            continue
        if p.startswith(("※", "関連記事", "参考", "免責")):
            continue

        picked.append(p)

        # 見出し + 2 段落で十分
        if len(picked) >= 3:
            break

    trimmed = "\n\n".join(picked)

    # ③ 最終安全弁：文字数で truncate
    if len(trimmed) > max_length:
        trimmed = trimmed[:max_length]

    return trimmed


# ==========================
# Gemini 要約
# ==========================

def summarize(text, api_key, max_retries=3):
    client = genai.Client(api_key=api_key)
    MAX_SUMMARY_LENGTH = 100

    prompt = f"""
以下の記事を要約してください。
条件:
・日本語
・80〜100文字
・事実のみ
・主語と固有名詞を省略しない

{text}
"""

    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )

            result = response.text.strip()

            if result:
                return result[:MAX_SUMMARY_LENGTH]


        except Exception:
            if attempt < max_retries - 1:
                sleep_seconds = random.randint(30, 90)
                time.sleep(sleep_seconds)
            else:
                raise

    return result[:MAX_SUMMARY_LENGTH]


# ==========================
# RSS取得
# ==========================

def fetch_rss(site):
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries[:site.get("max_items", 50)]:
        link = entry.get("link")
        title = entry.get("title", "")
        summary = entry.get("summary", "")

        if not link:
            continue

        items.append({
            "id": link,
            "text": f"{title}\n{summary}",
            "url": link
        })

    return items


# ==========================
# NVD API取得
# ==========================

def fetch_nvd(site):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "resultsPerPage": site.get("max_items", 100)
    }

    response = requests.get(url, params=params)
    response.raise_for_status()
    data = response.json()

    items = []
    threshold = float(site.get("cvss_threshold", 0))

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        metrics = cve.get("metrics", {})

        score = 0

        if "cvssMetricV31" in metrics:
            score = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV30" in metrics:
            score = float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV2" in metrics:
            score = float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])

        if score < threshold:
            continue

        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value")
                break

        if not cve_id:
            continue

        detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        items.append({
            "id": cve_id,
            "score": score,
            "text": (
                f"CVE ID: {cve_id}\n"
                f"CVSS Score: {score}\n\n"
                f"Description:\n{description}"
            ),
            "url": detail_url
        })

    return items


# ==========================
# Bluesky投稿
# ==========================

def post_bluesky(client, text, url):
    
    try:
        resp = requests.get(
            "https://cardyb.bsky.app/v1/extract",
            params={"url": url},
            timeout=10
        )
        card = resp.json()

        image_blob = None

        image_url = card.get("image")
        if image_url:
            img_resp = requests.get(image_url, timeout=10)
            if img_resp.status_code == 200:
                if len(img_resp.content) < 1_000_000:
                    upload = client.upload_blob(img_resp.content)
                    image_blob = upload.blob
                else:
                    logging.info("Image too large, skipping thumbnail")

        embed = models.AppBskyEmbedExternal.Main(
            external=models.AppBskyEmbedExternal.External(
                uri=url,
                title=card.get("title", ""),
                description=card.get("description", ""),
                thumb=image_blob
            )
        )

        client.send_post(text=text, embed=embed)

    except Exception as e:
        logging.warning(f"Embed failed: {e}")
        client.send_post(text=text)


# ==========================
# メイン処理
# ==========================

def main():

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s"
    )

    logger = logging.getLogger(__name__)

    gemini_key = os.environ.get("GEMINI_API_KEY")
    bluesky_id = os.environ.get("BLUESKY_IDENTIFIER")
    bluesky_pw = os.environ.get("BLUESKY_PASSWORD")

    if not bluesky_id or not bluesky_pw:
        raise ValueError("Bluesky credentials not set")

    if not gemini_key:
        raise ValueError("GEMINI_API_KEY not set")

    # BlueskyのID、Passのデバッグ
    #print("DEBUG ID:", bluesky_id)
    #print("DEBUG PW length:", len(bluesky_pw) if bluesky_pw else None)
    #print("ID raw repr:", repr(bluesky_id))
    #print("PW raw repr:", repr(bluesky_pw))


    client = Client(base_url="https://bsky.social")
    client.login(bluesky_id, bluesky_pw)

    config = load_config()
    settings = config.get("settings", {})
    force_test = settings.get("force_test_mode", False)
    sites = config.get("sites", {})

    def get_summary(text):

        # flash-lite 前提の本文最適化を必ず通す
        trimmed_text = body_trim(text)

        if force_test:
            # テスト時も「整形後本文」を使う（挙動差分防止）
            return trimmed_text[:200]
        return summarize(trimmed_text, gemini_key)

    MODE = settings.get("mode", "test").lower()

    if MODE not in ("test", "prod"):
        raise ValueError(f"Invalid MODE in site.yaml: {MODE}")

    logger.info("============================================")
    logger.info(f"Running MODE = {MODE}")
    logger.info("============================================")

    # ==========================
    # テストモード
    # ==========================
    if MODE == "test":

        logging.info("Test single real item (all enabled sites)")

        for site_key, site in sites.items():

            if not site.get("enabled", True):
                continue

            logging.info(f"Testing site: {site_key}")

            if site["type"] == "rss":
                items = fetch_rss(site)
            elif site["type"] == "nvd_api":
                items = fetch_nvd(site)
            else:
                continue

            if not items:
                continue

            item = items[0]

            summary = get_summary(item["text"])
            post_text = format_post(site, summary, item["url"], item)

            logging.info("[TEST] " + post_text)

            logging.info("Test completed")

            sleep_seconds = random.randint(45, 120)
            time.sleep(sleep_seconds)

            #最初のサイト1件のみにするときは以下を有効に、無効だと全サイト
            #return           # ← ★ ここが重要

        return

    # ==========================
    # 本番モード
    # ==========================
    state = load_state()

    if "_posted_cves" not in state:
        state["_posted_cves"] = []

    skip_first = settings.get("skip_existing_on_first_run", True)

    for site_key, site in sites.items():

        if not site.get("enabled", True):
            continue

        if site_key not in state:
            state[site_key] = []

        logging.info(f"Processing: {site_key}")

        if site["type"] == "rss":
            items = fetch_rss(site)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site)
        else:
            logging.warning(f"Unknown type: {site['type']}")
            continue

        if not state[site_key] and skip_first:
            logging.info("Initial run → skip existing")
            state[site_key] = [item["id"] for item in items]
            continue

        new_items = [
            item for item in items
            if item["id"] not in state[site_key]
        ]

        if not new_items:
            logging.info("No new items")
            continue

        for item in new_items:

            cve_id = item.get("id")

            if site_key == "jvn" and cve_id in state["_posted_cves"]:
                logging.info(f"Skip duplicate CVE (JVN): {cve_id}")
                continue

            summary = get_summary(item["text"])
            post_text = format_post(site, summary, item["url"], item)

            post_bluesky(client, post_text, item["url"])
            sleep_seconds = random.randint(30, 90)
            time.sleep(sleep_seconds)
            logging.info("Posted successfully")

            state[site_key].append(item["id"])

            if site_key == "nvd":
                state["_posted_cves"].append(item["id"])

        save_state(state)


if __name__ == "__main__":
    main()

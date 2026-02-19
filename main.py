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
from datetime import datetime, timedelta, timezone

# ==========================
# 定数
# ==========================

SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"
MAX_POST_LENGTH = 140


# ==========================
# 時刻ユーティリティ
# ==========================

def utc_now():
    return datetime.now(timezone.utc)

def isoformat(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ==========================
# 設定 / state
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
        except Exception:
            return {}

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


# ==========================
# 共通ユーティリティ
# ==========================

def cvss_to_severity(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def body_trim(text, max_len=2500):
    """
    Gemini に渡す前の本文前処理（常時実行）
    """
    lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 10]
    trimmed = "\n".join(lines[:6])
    return trimmed[:max_len]


def format_post(site, summary, url, item):
    body = summary.replace("\n", " ").strip()

    if site["type"] == "nvd_api":
        cve_id = item["id"]
        score = item.get("score", 0)
        severity = cvss_to_severity(score)

        base_text = (
            f"{cve_id}\n"
            f"CVSS {score} | {severity}\n\n"
            f"{body}"
        )
    else:
        base_text = body

    if len(base_text) > MAX_POST_LENGTH:
        base_text = base_text[:MAX_POST_LENGTH - 1] + "…"

    return base_text


# ==========================
# Gemini 要約
# ==========================

def summarize(text, api_key, max_retries=3):
    client = genai.Client(api_key=api_key)

    prompt = f"""
以下を日本語で簡潔に要約してください。
事実のみ。
誇張なし。
主語と固有名詞を省略しない。
100文字以内。

{text}
"""

    for attempt in range(max_retries):
        try:
            resp = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )
            result = resp.text.strip()
            if result:
                return result[:100]
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(random.randint(30, 90))
            else:
                raise

    return text[:100]


# ==========================
# RSS
# ==========================

def fetch_rss(site):
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries[:site.get("max_items", 1)]:
        link = entry.get("link")
        if not link:
            continue

        items.append({
            "id": link,
            "text": f"{entry.get('title','')}\n{entry.get('summary','')}",
            "url": link
        })

    return items


# ==========================
# NVD（期間指定）
# ==========================

def fetch_nvd(site, pub_start, pub_end):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "resultsPerPage": site.get("max_items", 50),
        "pubStartDate": isoformat(pub_start),
        "pubEndDate": isoformat(pub_end),
    }

    logging.info(
        f"NVD query: {params['pubStartDate']} → {params['pubEndDate']}"
    )

    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    threshold = float(site.get("cvss_threshold", 0))
    items = []

    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        metrics = cve.get("metrics", {})

        score = 0
        if "cvssMetricV31" in metrics:
            score = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV30" in metrics:
            score = float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV2" in metrics:
            score = float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])

        if not cve_id or score < threshold:
            continue

        items.append({
            "id": cve_id,
            "score": score,
            "text": cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        })

    return items


# ==========================
# Bluesky 投稿
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
            img = requests.get(image_url, timeout=10)
            if img.status_code == 200 and len(img.content) < 1_000_000:
                upload = client.upload_blob(img.content)
                image_blob = upload.blob

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
# main
# ==========================

def main():

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s:%(message)s"
    )

    config = load_config()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    MODE = settings.get("mode", "test").lower()
    force_test = settings.get("force_test_mode", False)
    skip_first = settings.get("skip_existing_on_first_run", True)

    # 元 state を読み込み、commit 用に deep copy
    original_state = load_state()
    state = json.loads(json.dumps(original_state))
    state_dirty = False

    # --- Gemini / Bluesky ---
    gemini_key = os.environ.get("GEMINI_API_KEY")
    bluesky_id = os.environ.get("BLUESKY_IDENTIFIER")
    bluesky_pw = os.environ.get("BLUESKY_PASSWORD")

    if MODE == "prod":
        client = Client(base_url="https://bsky.social")
        client.login(bluesky_id, bluesky_pw)

    def get_summary(text):
        # test + force_test_mode では Gemini を使わない
        return text[:100] if force_test else summarize(text, gemini_key)

    now = utc_now()

    # ==========================
    # サイト処理
    # ==========================

    for site_key, site in sites.items():

        if not site.get("enabled", False):
            continue

        logging.info(f"Processing: {site_key}")

        # --------------------------
        # state 正規化（後方互換）
        # --------------------------

        raw = state.get(site_key)

        if isinstance(raw, list):
            if MODE == "test":
                logging.info(
                    f"Migrate state [{site_key}]: list → dict (TEST: not saved)"
                )
            else:
                logging.info(
                    f"Migrate state [{site_key}]: list → dict"
                )

            state[site_key] = {
                "posted_ids": raw
            }
            state_dirty = True

        site_state = state.setdefault(site_key, {"posted_ids": []})

        # ---------- NVD ----------
        if site["type"] == "nvd_api":

            last_checked = site_state.get("last_checked_at")

            if not last_checked:
                logging.info("NVD initial run → last 1 day")
                pub_start = now - timedelta(days=1)
            else:
                pub_start = datetime.fromisoformat(
                    last_checked.replace("Z", "+00:00")
                )

            pub_end = now
            items = fetch_nvd(site, pub_start, pub_end)

        # ---------- RSS ----------
        elif site["type"] == "rss":
            items = fetch_rss(site)

        else:
            continue

        # ---------- TEST ----------
        if MODE == "test":

            if not items:
                logging.info(f"[TEST] {site_key}: no new items")
                continue

            item = items[0]
            trimmed = body_trim(item["text"])
            summary = get_summary(trimmed)
            post_text = format_post(site, summary, item["url"], item)

            logging.info("[TEST]\n" + post_text)
            continue

        # ---------- PROD ----------

        if site["type"] == "rss" and not site_state["posted_ids"] and skip_first:
            logging.info("Initial run → skip existing")
            site_state["posted_ids"] = [item["id"] for item in items]
            state_dirty = True
            continue

        if not items:
            logging.info(f"{site_key}: no new items")
            continue

        for item in items:
            if item["id"] in site_state["posted_ids"]:
                logging.info(f"Skip known: {item['id']}")
                continue

            trimmed = body_trim(item["text"])
            summary = get_summary(trimmed)
            post_text = format_post(site, summary, item["url"], item)

            post_bluesky(client, post_text, item["url"])
            time.sleep(random.randint(30, 90))

            site_state["posted_ids"].append(item["id"])
            state_dirty = True

            if site["type"] == "nvd_api":
                site_state["last_checked_at"] = isoformat(now)

    # ==========================
    # state commit（prod & 正常終了）
    # ==========================

    if MODE == "prod" and state_dirty:
        save_state(state)


if __name__ == "__main__":
    main()

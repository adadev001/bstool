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

# ==================================================
# 定数
# ==================================================

SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"
MAX_POST_LENGTH = 140

# RSS / API の時刻ズレ耐性用（任意だが安全）
SAFE_OVERLAP = timedelta(minutes=5)

# ==================================================
# 時刻ユーティリティ
# ==================================================

def utc_now():
    return datetime.now(timezone.utc)

def isoformat(dt: datetime) -> str:
    """UTC datetime を NVD / state 共通 ISO 文字列へ"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_iso(ts: str) -> datetime:
    """state に保存された ISO 文字列を datetime に戻す"""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

# ==================================================
# 設定 / state I/O
# ==================================================

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

def save_state(state: dict):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

# ==================================================
# 共通ユーティリティ
# ==================================================

def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

def body_trim(text: str, max_len: int = 2500) -> str:
    """
    Gemini に渡す前の本文前処理（常時実行）
    - 極端に短い行を除外
    - 冒頭から数段落のみ使用
    """
    lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 10]
    trimmed = "\n".join(lines[:6])
    return trimmed[:max_len]

def format_post(site: dict, summary: str, url: str, item: dict) -> str:
    """
    投稿本文生成
    - NVD は CVE / CVSS 情報を付加
    - 最終的に MAX_POST_LENGTH 以内へ
    """
    body = summary.replace("\n", " ").strip()

    if site["type"] == "nvd_api":
        cve_id = item["id"]
        score = item.get("score", 0)
        severity = cvss_to_severity(score)
        base = (
            f"{cve_id}\n"
            f"CVSS {score} | {severity}\n\n"
            f"{body}"
        )
    else:
        base = body

    if len(base) > MAX_POST_LENGTH:
        base = base[:MAX_POST_LENGTH - 1] + "…"

    return base

# ==================================================
# Gemini 要約
# ==================================================

def summarize(text: str, api_key: str, max_retries: int = 3) -> str:
    """
    Gemini 2.5 flash-lite による要約
    force_test_mode=false の場合のみ呼ばれる
    """
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

    # fallback
    return text[:100]

# ==================================================
# RSS 取得（時間軸主導）
# ==================================================

def fetch_rss(site: dict, start: datetime, end: datetime):
    """
    RSS を取得し、start < entry_time <= end のものだけ返す
    """
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries:
        # RSS の時刻は published / updated を優先
        published = (
            entry.get("published_parsed")
            or entry.get("updated_parsed")
        )

        if not published:
            continue

        entry_time = datetime.fromtimestamp(
            time.mktime(published), tz=timezone.utc
        )

        if not (start < entry_time <= end):
            continue

        link = entry.get("link")
        if not link:
            continue

        items.append({
            "id": link,
            "text": f"{entry.get('title','')}\n{entry.get('summary','')}",
            "url": link,
            "entry_time": entry_time
        })

        if len(items) >= site.get("max_items", 1):
            break

    return items

# ==================================================
# NVD 取得（時間軸主導）
# ==================================================

def fetch_nvd(site: dict, start: datetime, end: datetime):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "resultsPerPage": site.get("max_items", 50),
        "pubStartDate": isoformat(start),
        "pubEndDate": isoformat(end),
    }

    logging.info(f"NVD query: {params['pubStartDate']} → {params['pubEndDate']}")

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
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return items

# ==================================================
# Bluesky 投稿
# ==================================================

def post_bluesky(client: Client, text: str, url: str):
    """
    OGP が取れれば embed 付き、失敗したら text のみ
    """
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

# ==================================================
# main
# ==================================================

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

    # 元 state を保持（commit 方式）
    original_state = load_state()
    state = json.loads(json.dumps(original_state))
    state_dirty = False

    now = utc_now()

    # --- 外部サービス ---
    gemini_key = os.environ.get("GEMINI_API_KEY")
    bluesky_id = os.environ.get("BLUESKY_IDENTIFIER")
    bluesky_pw = os.environ.get("BLUESKY_PASSWORD")

    if MODE == "prod":
        client = Client(base_url="https://bsky.social")
        client.login(bluesky_id, bluesky_pw)

    def get_summary(text: str) -> str:
        # test + force_test_mode では Gemini を絶対に呼ばない
        return text[:100] if force_test else summarize(text, gemini_key)

    # ==================================================
    # サイト処理
    # ==================================================

    for site_key, site in sites.items():

        if not site.get("enabled", False):
            continue

        logging.info(f"Processing: {site_key}")

        # --- state 正規化 ---
        raw = state.get(site_key)

        # 旧 list state → dict へ移行
        if isinstance(raw, list):
            logging.info(f"Migrate state [{site_key}]: list → dict")
            state[site_key] = {"last_checked_at": None}
            state_dirty = True

        site_state = state.setdefault(site_key, {})

        last_checked = site_state.get("last_checked_at")
        if last_checked:
            start = parse_iso(last_checked) - SAFE_OVERLAP
        else:
            start = now - timedelta(days=1)

        end = now

        # --- 取得 ---
        if site["type"] == "rss":
            items = fetch_rss(site, start, end)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site, start, end)
        else:
            continue

        # --- TEST モード ---
        if MODE == "test":
            if items:
                item = items[0]
                trimmed = body_trim(item["text"])
                summary = get_summary(trimmed)
                post_text = format_post(site, summary, item["url"], item)
                logging.info("[TEST]\n" + post_text)
            continue

        # --- PROD 初回スキップ ---
        if not last_checked and skip_first:
            logging.info("Initial run → skip existing")
            site_state["last_checked_at"] = isoformat(now)
            state_dirty = True
            continue

        # --- PROD 投稿 ---
        for item in items:
            trimmed = body_trim(item["text"])
            summary = get_summary(trimmed)
            post_text = format_post(site, summary, item["url"], item)

            post_bluesky(client, post_text, item["url"])
            time.sleep(random.randint(30, 90))

        # --- commit（サイト単位） ---
        site_state["last_checked_at"] = isoformat(now)
        state_dirty = True

    # ==================================================
    # state commit（prod & 正常終了時のみ）
    # ==================================================

    if MODE == "prod" and state_dirty:
        save_state(state)

if __name__ == "__main__":
    main()

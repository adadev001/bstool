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

def parse_iso(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

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

# ==========================
# NVD 脆弱性タイプ分類
# ==========================

def classify_vuln_type(text: str) -> str:
    """
    NVD / JVD 共通で使える軽量分類器
    """
    t = text.lower()

    if any(k in t for k in [
        "remote code execution",
        "arbitrary code execution",
        "execute arbitrary code",
        "code execution"
    ]):
        return "任意コード実行"

    if any(k in t for k in [
        "denial of service",
        "dos",
        "service crash"
    ]):
        return "サービス拒否（DoS）"

    if any(k in t for k in [
        "information disclosure",
        "information leak",
        "leak",
        "expose sensitive"
    ]):
        return "情報漏えい"

    if any(k in t for k in [
        "privilege escalation",
        "elevation of privilege"
    ]):
        return "権限昇格"

    return "セキュリティ上の問題"

# ==========================
# 本文前処理
# ==========================

def body_trim(text, max_len=2500, site_type=None):
    """
    Gemini に渡す前の本文前処理
    - RSS: 従来通り
    - NVD: 意味のある文のみ抽出
    """

    if site_type == "nvd_api":
        lines = [
            l.strip()
            for l in text.splitlines()
            if any(k in l.lower() for k in [
                "allow", "allows", "could", "can",
                "vulnerability", "attack", "execute",
                "disclosure", "denial"
            ])
        ]
        joined = " ".join(lines)
        return joined[:max_len]

    # RSS / その他
    lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 10]
    trimmed = "\n".join(lines[:6])
    return trimmed[:max_len]

# ==========================
# 投稿文生成
# ==========================

def format_post(site, summary, url, item):
    body = summary.replace("\n", " ").strip()

    if site["type"] == "nvd_api":
        score = item.get("score", 0)
        severity = cvss_to_severity(score)
        vuln_type = classify_vuln_type(body)

        # タイトルから CVE を排除
        title = f"[{severity}] {vuln_type}の脆弱性"

        base_text = (
            f"{title}\n\n"
            f"{body}\n\n"
            f"CVSS {score} | {severity}\n"
            f"{item['id']}"
        )
    else:
        base_text = body

    if len(base_text) > MAX_POST_LENGTH:
        base_text = base_text[:MAX_POST_LENGTH - 1] + "…"

    return base_text

# ==========================
# Gemini 要約
# ==========================

def summarize(text, api_key, site_type=None, max_retries=3):
    client = genai.Client(api_key=api_key)

    # --- NVD 専用指示 ---
    if site_type == "nvd_api":
        prompt = f"""
以下の観点を必ず含め、日本語80〜100文字で要約してください。

- 脆弱性の種類
- 影響を受ける対象
- 攻撃者が可能になる行為

注意:
- CVE番号は本文に含めない
- 不明な点は「可能性がある」と表現
- 事実のみ

{text}
"""
    else:
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
                break

    # --- fallback（LLM失敗時） ---
    vuln_type = classify_vuln_type(text)
    return f"{vuln_type}に関する脆弱性が確認されました。影響範囲や条件については現在調査中です。"

# ==========================
# RSS（時間軸対応）
# ==========================

def fetch_rss(site, since, until):
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries:
        published = entry.get("published_parsed")
        if not published:
            continue

        entry_time = datetime.fromtimestamp(
            time.mktime(published),
            tz=timezone.utc
        )

        if not (since < entry_time <= until):
            continue

        items.append({
            "id": entry.get("link"),
            "text": f"{entry.get('title','')}\n{entry.get('summary','')}",
            "url": entry.get("link"),
            "entry_time": entry_time
        })

    return items[: site.get("max_items", 1)]

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

        # --- description を本文として使用 ---
        description = ""
        descs = cve.get("descriptions", [])
        if descs:
            description = descs[0].get("value", "")

        items.append({
            "id": cve_id,
            "score": score,
            "text": description,
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

    original_state = load_state()
    state = json.loads(json.dumps(original_state))  # deep copy
    state_dirty = False

    gemini_key = os.environ.get("GEMINI_API_KEY")

    if MODE == "prod":
        client = Client(base_url="https://bsky.social")
        client.login(
            os.environ.get("BLUESKY_IDENTIFIER"),
            os.environ.get("BLUESKY_PASSWORD"),
        )

    def get_summary(text, site_type):
        return text[:100] if force_test else summarize(text, gemini_key, site_type)

    now = utc_now()

    for site_key, site in sites.items():

        if not site.get("enabled", False):
            continue

        logging.info(f"Processing: {site_key}")

        raw = state.get(site_key)

        # --- state 正規化（list → dict） ---
        if isinstance(raw, list):
            logging.info(
                f"Migrate state [{site_key}]: list → dict"
                + (" (TEST: not saved)" if MODE == "test" else "")
            )
            state[site_key] = {
                "last_checked_at": None,
                "posted_ids": raw  # 将来 JVD/NVD 重複防止用
            }
            if MODE == "prod":
                state_dirty = True

        site_state = state.setdefault(site_key, {})
        last_checked = site_state.get("last_checked_at")

        if not last_checked:
            if skip_first:
                logging.info(f"{site_key}: initial run → skip existing")
                site_state["last_checked_at"] = isoformat(now)
                if MODE == "prod":
                    state_dirty = True
                continue
            since = now - timedelta(days=1)
        else:
            since = parse_iso(last_checked)

        until = now

        # ---------- fetch ----------
        if site["type"] == "rss":
            items = fetch_rss(site, since, until)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site, since, until)
        else:
            continue

        if not items:
            logging.info(f"{site_key}: no new items")
            if MODE == "prod":
                site_state["last_checked_at"] = isoformat(now)
                state_dirty = True
            continue

        # ---------- TEST ----------
        if MODE == "test":
            item = items[0]
            summary = get_summary(
                body_trim(item["text"], site_type=site["type"]),
                site["type"]
            )
            post_text = format_post(site, summary, item["url"], item)
            logging.info("[TEST]\n" + post_text)
            continue

        # ---------- PROD ----------
        for item in items:
            summary = get_summary(
                body_trim(item["text"], site_type=site["type"]),
                site["type"]
            )
            post_text = format_post(site, summary, item["url"], item)
            post_bluesky(client, post_text, item["url"])
            time.sleep(random.randint(30, 90))

        site_state["last_checked_at"] = isoformat(now)
        state_dirty = True

    if MODE == "prod" and state_dirty:
        save_state(state)

if __name__ == "__main__":
    main()
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

# =========================================================
# 定数定義
# =========================================================
SITES_FILE = "sites.yaml"             # サイト設定ファイル
STATE_FILE = "processed_urls.json"    # 投稿済み管理ファイル
MAX_POST_LENGTH = 140                 # 投稿本文の最大文字数（X移植前提）
SUMMARY_HARD_LIMIT = 80               # 要約文字数の安全上限
POSTED_ID_RETENTION_DAYS = 30         # posted_id の保持日数
POSTED_ID_MAX = 1000                  # posted_id の最大件数

# =========================================================
# 時刻ユーティリティ
# =========================================================
def utc_now():
    """UTC現在時刻を返す"""
    return datetime.now(timezone.utc)

def isoformat(dt: datetime) -> str:
    """datetime → ISO8601 文字列"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_iso(ts: str) -> datetime:
    """ISO8601文字列 → datetime"""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

# =========================================================
# 設定 / state 読み込み
# =========================================================
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
    """state を JSON ファイルに保存"""
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

# =========================================================
# state 正規化（後方互換対応）
# =========================================================
def normalize_site_state(site_key, raw_state, now, mode, site_type):
    """
    - list形式だった posted_ids を dict に変換
    - RSS サイトは posted_ids を持たない（State v2）
    - last_checked_at が未設定の場合は初期値 None
    """
    migrated = False

    if raw_state is None:
        # 新規 state
        state_base = {"last_checked_at": None}
        if site_type not in ("rss",):
            state_base["posted_ids"] = {}
            state_base["retry_ids"] = {}  # retry 用辞書
        return state_base, False

    # list → dict 移行（旧形式）
    if isinstance(raw_state, list):
        logging.info(
            f"Migrate state [{site_key}]: list → dict"
            + (" (TEST: not saved)" if mode == "test" else "")
        )
        return {
            "last_checked_at": None,
            "posted_ids": {cid: isoformat(now) for cid in raw_state},
            "retry_ids": {},
        }, True

    # RSS は posted_ids を削除
    if site_type == "rss":
        raw_state.pop("posted_ids", None)
        raw_state.setdefault("last_checked_at", None)
        return raw_state, migrated

    # posted_ids の list → dict 変換
    posted = raw_state.get("posted_ids")
    if isinstance(posted, list):
        raw_state["posted_ids"] = {cid: isoformat(now) for cid in posted}
        migrated = True

    raw_state.setdefault("posted_ids", {})
    raw_state.setdefault("retry_ids", {})
    raw_state.setdefault("last_checked_at", None)
    return raw_state, migrated

# =========================================================
# posted_ids 管理
# =========================================================
def prune_posted_ids(posted_ids: dict, now: datetime):
    """
    - 保持期間超過の posted_id を削除
    - 件数上限を超えた場合、古い順に削除
    """
    before = len(posted_ids)
    cutoff = now - timedelta(days=POSTED_ID_RETENTION_DAYS)

    expired = [cid for cid, ts in posted_ids.items() if parse_iso(ts) < cutoff]
    for cid in expired:
        del posted_ids[cid]

    if len(posted_ids) > POSTED_ID_MAX:
        logging.warning(f"posted_ids exceeded max ({POSTED_ID_MAX}), trimming old entries")
        sorted_items = sorted(posted_ids.items(), key=lambda x: parse_iso(x[1]))
        for cid, _ in sorted_items[:-POSTED_ID_MAX]:
            del posted_ids[cid]

    return before - len(posted_ids)

# =========================================================
# 共通ユーティリティ
# =========================================================
def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

def safe_truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"

# =========================================================
# 本文前処理
# =========================================================
def body_trim(text, max_len=2500, site_type=None):
    """
    - NVD/JVN は脆弱性関連文のみ抽出
    - RSS は最初の数行を抽出
    """
    if site_type in ("nvd_api", "jvn"):
        lines = [
            l.strip()
            for l in text.splitlines()
            if any(k in l.lower() for k in [
                "allow", "allows", "could", "can",
                "vulnerability", "attack", "execute",
                "disclosure", "denial"
            ])
        ]
        return " ".join(lines)[:max_len]

    lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 10]
    return "\n".join(lines[:6])[:max_len]

# =========================================================
# CVE 既投稿チェック
# =========================================================
def is_cve_already_posted(cid, site_type, state):
    """
    RSS: CVE はチェックしない
    JVN / NVD: NVD 側で既投稿の CVE はスキップ
    """
    if not cid or site_type == "rss":
        return False
    posted_ids = state.get("nvd", {}).get("posted_ids", {})
    return cid in posted_ids

# =========================================================
# 投稿文生成
# =========================================================
def format_post(site, summary, item):
    summary_text = safe_truncate(summary.replace("\n", " "), MAX_POST_LENGTH)

    if site["type"] in ("nvd_api", "jvn"):
        score = item.get("score", 0)
        severity = cvss_to_severity(score)
        cve_line = f"{item['id']} CVSS {score} | {severity}"
        return summary_text, cve_line

    return summary_text, None

# =========================================================
# Gemini 要約
# =========================================================
def summarize(text, api_key, site_type=None):
    client = genai.Client(api_key=api_key)

    prompt = (
        """
以下の観点を必ず含め、日本語80文字以内で要約してください。
- 脆弱性の内容
- 影響を受ける対象
- 攻撃者が可能になる行為
※ CVE番号は含めない
"""
        if site_type in ("nvd_api", "jvn")
        else "以下を日本語で簡潔に要約してください。80文字以内。"
    ) + f"\n{text}"

    for attempt in (1, 2):
        try:
            time.sleep(random.uniform(0.5, 1.5))
            resp = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )
            return safe_truncate(resp.text.strip(), SUMMARY_HARD_LIMIT)
        except Exception as e:
            msg = str(e)
            if attempt == 1 and ("429" in msg or "503" in msg):
                logging.warning("Gemini summarize retry due to 429/503")
                time.sleep(2)
                continue
            logging.error(f"Gemini summarize failed: {e}")
            break

    # フォールバック文言
    return "要約生成に失敗したため、脆弱性の存在のみ通知します。"

# =========================================================
# データ取得
# =========================================================
def fetch_rss(site, since=None, until=None):
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries[: site.get("max_items", 1)]:
        items.append({
            "id": entry.get("link"),
            "text": f"{entry.get('title','')}\n{entry.get('summary','')}",
            "url": entry.get("link"),
        })
    return items

def fetch_nvd(site, start, end):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": site.get("max_items", 50),
        "pubStartDate": isoformat(start),
        "pubEndDate": isoformat(end),
    }

    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    items = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cid = cve.get("id")
        desc = cve.get("descriptions", [{}])[0].get("value", "")
        items.append({
            "id": cid,
            "score": 0,
            "text": desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}"
        })
    return items

def fetch_jvn(site, since, until):
    feed = feedparser.parse(site["url"])
    items = []

    for entry in feed.entries:
        cve_ids = [t for t in entry.get("tags", []) if t.get("term", "").startswith("CVE-")]
        if not cve_ids:
            continue

        items.append({
            "id": cve_ids[0]["term"],
            "score": site.get("default_cvss", 0),
            "text": entry.get("summary", ""),
            "url": entry.get("link")
        })

    return items[: site.get("max_items", 1)]

# =========================================================
# Bluesky 投稿（embed 対応）
# =========================================================
def post_bluesky(client, text, url):
    """
    - text は要約文
    - url は embed 用
    """
    embed = models.AppBskyFeedPost(
        text=text,
        embed=models.AppBskyFeedPostEmbedExternal(
            external=models.AppBskyFeedDefsExternal(
                uri=url
            )
        )
    )
    client.send_post(embed)

# =========================================================
# main
# =========================================================
def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    config = load_config()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    MODE = settings.get("mode", "test").lower()
    force_test = settings.get("force_test_mode", False)
    skip_first = settings.get("skip_existing_on_first_run", True)

    state = load_state()
    state_dirty = False
    now = utc_now()
    gemini_key = os.environ.get("GEMINI_API_KEY")

    if MODE == "prod":
        client = Client()
        client.login(
            os.environ["BLUESKY_IDENTIFIER"],
            os.environ["BLUESKY_PASSWORD"]
        )

    for site_key, site in sites.items():
        if not site.get("enabled"):
            continue

        logging.info(f"[{site_key}] ---")

        site_state, migrated = normalize_site_state(
            site_key, state.get(site_key), now, MODE, site["type"]
        )
        state[site_key] = site_state
        if migrated:
            state_dirty = True

        last_checked = site_state.get("last_checked_at")
        first_skip = False

        if last_checked is None:
            since = now - timedelta(days=1)
            first_skip = skip_first and MODE == "prod"
        else:
            since = parse_iso(last_checked)

        until = now

        # データ取得
        if site["type"] == "rss":
            items = fetch_rss(site, since, until)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site, since, until)
        elif site["type"] == "jvn":
            items = fetch_jvn(site, since, until)
        else:
            continue

        if first_skip:
            logging.info(f"[{site_key}] 初回実行のため既存記事 {len(items)} 件をスキップ")
            for item in items:
                # 初回は retry 対象外
                site_state.setdefault("retry_ids", {})[item["id"]] = {
                    "status": "skipped",
                    "last_attempt_at": isoformat(now),
                    "retry_count": 0
                }
        else:
            for item in items:
                cid = item.get("id")
                retry_entry = site_state.setdefault("retry_ids", {}).get(cid, {})

                # 既投稿チェック
                if is_cve_already_posted(cid, site["type"], state):
                    logging.info(f"[{site_key}] 既投稿 CVE スキップ: {cid}")
                    site_state["retry_ids"][cid] = {
                        "status": "skipped",
                        "last_attempt_at": isoformat(now),
                        "retry_count": retry_entry.get("retry_count", 0)
                    }
                    continue

                # 本文前処理
                trimmed = body_trim(item["text"], site_type=site["type"])

                # 要約
                summary = (
                    trimmed[:SUMMARY_HARD_LIMIT]
                    if force_test
                    else summarize(trimmed, gemini_key, site["type"])
                )

                post_text, cve_line = format_post(site, summary, item)
                full_text = f"{post_text}\n{cve_line}" if cve_line else post_text

                try:
                    if MODE == "test":
                        logging.info("[TEST]\n" + full_text)
                        post_status = "success"
                    else:
                        post_bluesky(client, post_text, item["url"])
                        post_status = "success"
                except Exception as e:
                    logging.error(f"[{site_key}] 投稿失敗: {e}")
                    post_status = "failed"

                # state 更新（retry_ids）
                retry_count = retry_entry.get("retry_count", 0)
                site_state["retry_ids"][cid] = {
                    "status": post_status,
                    "last_attempt_at": isoformat(now),
                    "retry_count": retry_count + 1
                }

                # posted_ids 更新（成功時のみ）
                if post_status == "success" and cid and site["type"] != "rss":
                    state.setdefault("nvd", {}).setdefault("posted_ids", {})[cid] = isoformat(now)
                    prune_posted_ids(state["nvd"]["posted_ids"], now)

        # 最終更新
        site_state["last_checked_at"] = isoformat(now)
        state_dirty = True

    if MODE == "prod" and state_dirty:
        save_state(state)

if __name__ == "__main__":
    main()
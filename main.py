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
# サイト設定ファイル（単一ソース管理）
SITES_FILE = "sites.yaml"

# 投稿状態管理ファイル（長期無停止運用の要）
STATE_FILE = "processed_urls.json"

# 投稿本文最大文字数（将来X移植前提）
MAX_POST_LENGTH = 140

# Gemini要約の安全上限（強制80文字）
SUMMARY_HARD_LIMIT = 80

# posted_id保持日数（古いIDの自然消滅）
POSTED_ID_RETENTION_DAYS = 30

# posted_id最大保持件数（肥大化防止）
POSTED_ID_MAX = 1000

# 1回の実行で処理するretry上限
# → 無限再試行防止
RETRY_LIMIT = 3


# =========================================================
# 時刻ユーティリティ
# =========================================================
def utc_now():
    """UTC現在時刻を取得（全処理はUTC基準）"""
    return datetime.now(timezone.utc)

def isoformat(dt: datetime) -> str:
    """datetime → ISO8601文字列変換（Z付き）"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_iso(ts: str) -> datetime:
    """ISO8601文字列 → datetime"""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# =========================================================
# 設定 / state 読み込み
# =========================================================
def load_config():
    """sites.yaml読み込み（単一設定ソース）"""
    with open(SITES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_state():
    """
    state読み込み。
    初回起動時は空dictを返す。
    """
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_state(state):
    """
    state保存。
    prodモード時のみ保存される。
    """
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


# =========================================================
# state 正規化
# =========================================================
def normalize_site_state(site_key, raw_state, now):
    """
    過去形式との互換維持。

    保証する構造:
    {
        last_checked_at,
        posted_ids,
        retry_ids,
        entries,
        known_cves
    }
    """

    if raw_state is None:
        # 初回実行時
        return {
            "last_checked_at": None,
            "posted_ids": {},
            "retry_ids": [],
            "entries": {},
            "known_cves": []
        }

    # 不足キー補完
    raw_state.setdefault("posted_ids", {})
    raw_state.setdefault("retry_ids", [])
    raw_state.setdefault("entries", {})
    raw_state.setdefault("known_cves", [])
    return raw_state


# =========================================================
# posted_id pruning
# =========================================================
def prune_posted_ids(posted_ids: dict, now: datetime):
    """
    posted_idsの肥大化防止。

    ① 保持期限超過削除
    ② 最大件数超過削除
    """

    cutoff = now - timedelta(days=POSTED_ID_RETENTION_DAYS)

    # 期限切れ削除
    expired = [cid for cid, ts in posted_ids.items() if parse_iso(ts) < cutoff]
    for cid in expired:
        del posted_ids[cid]

    # 件数上限削除
    if len(posted_ids) > POSTED_ID_MAX:
        sorted_items = sorted(posted_ids.items(), key=lambda x: parse_iso(x[1]))
        for cid, _ in sorted_items[:-POSTED_ID_MAX]:
            del posted_ids[cid]


# =========================================================
# CVSS → Severity
# =========================================================
def cvss_to_severity(score: float) -> str:
    """
    CVSSスコアを文字列分類へ変換。
    """
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


# =========================================================
# 文字数安全制御
# =========================================================
def safe_truncate(text: str, limit: int) -> str:
    """
    文字数超過時に…で安全切り捨て。
    """
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


# =========================================================
# Gemini要約
# =========================================================
def summarize(text, api_key, site_type=None):
    """
    正常時:
        80文字以内要約を返す
    失敗時:
        "__FALLBACK__" を返す（成功扱いにしない）
    """

    client = genai.Client(api_key=api_key)

    prompt = "80文字以内で事実のみ日本語要約\n" + text

    for attempt in (1, 2):
        try:
            # API負荷分散ジッター
            time.sleep(random.uniform(0.5, 1.5))

            resp = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )

            return safe_truncate(resp.text.strip(), SUMMARY_HARD_LIMIT)

        except Exception as e:
            # 429 / 503 は1回だけ再試行
            if attempt == 1 and ("429" in str(e) or "503" in str(e)):
                time.sleep(2)
                continue
            break

    # retry対象
    return "__FALLBACK__"


# =========================================================
# NVD取得
# =========================================================
def fetch_nvd(site, start, end):
    """
    NVD API取得。

    429発生時:
        Exception("NVD_429") を投げる
        → mainでretry思想に統合
    """

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "resultsPerPage": site.get("max_items", 50),
        "pubStartDate": isoformat(start),
        "pubEndDate": isoformat(end),
    }

    resp = requests.get(url, params=params, timeout=30)

    if resp.status_code == 429:
        # retry思想へ統合
        raise Exception("NVD_429")

    resp.raise_for_status()
    data = resp.json()

    threshold = float(site.get("cvss_threshold", 0))
    items = []

    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue

        score = 0
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                score = float(metrics[key][0]["cvssData"]["baseScore"])
                break

        if score < threshold:
            continue

        desc = cve.get("descriptions", [{}])[0].get("value", "")

        items.append({
            "id": cid,
            "score": score,
            "text": desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}"
        })

    return items


# =========================================================
# main
# =========================================================
def main():

    logging.basicConfig(level=logging.INFO)

    config = load_config()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    MODE = settings.get("mode", "test").lower()
    skip_first = settings.get("skip_existing_on_first_run", True)

    state = load_state()
    now = utc_now()

    gemini_key = os.environ.get("GEMINI_API_KEY")

    # =====================================================
    # Blueskyログイン（prodのみ）
    # =====================================================
    if MODE == "prod":
        client = Client(base_url="https://bsky.social")
        client.login(
            os.environ.get("BLUESKY_IDENTIFIER"),
            os.environ.get("BLUESKY_PASSWORD")
        )

    # =====================================================
    # サイト単位処理
    # =====================================================
    for site_key, site in sites.items():

        if not site.get("enabled", False):
            continue

        # state正規化
        site_state = normalize_site_state(site_key, state.get(site_key), now)
        state[site_key] = site_state

        # =====================================================
        # retry優先処理
        # =====================================================
        # retry_idsは新規取得より先に処理
        retry_queue = site_state.get("retry_ids", [])
        retry_targets = retry_queue[:RETRY_LIMIT]

        # 今回処理分をキューから除去
        site_state["retry_ids"] = retry_queue[RETRY_LIMIT:]

        # =====================================================
        # データ取得（例: NVD）
        # =====================================================
        try:
            if site["type"] == "nvd_api":
                items = fetch_nvd(site, now - timedelta(hours=3), now)
            else:
                continue
        except Exception as e:
            if str(e) == "NVD_429":
                # last_checked_at更新しない
                logging.warning("NVD 429 → 次回再試行")
                continue
            raise

        # retry対象を統合
        items = items + [
            site_state["entries"].get(rid, {})
            for rid in retry_targets
            if rid in site_state["entries"]
        ]

        # =====================================================
        # 投稿処理ループ
        # =====================================================
        for item in items:

            entry_key = item.get("id")

            summary = summarize(item.get("text", ""), gemini_key, site["type"])

            # fallbackは成功扱いにしない
            if summary == "__FALLBACK__":
                retry_count = site_state["entries"].get(entry_key, {}).get("retry_count", 0) + 1

                if retry_count <= RETRY_LIMIT:
                    site_state.setdefault("retry_ids", []).append(entry_key)

                site_state["entries"][entry_key] = {
                    "status": "failed",
                    "retry_count": retry_count,
                    "last_tried_at": isoformat(now)
                }
                continue

            post_text = safe_truncate(summary, MAX_POST_LENGTH)

            try:
                if MODE == "prod":
                    client.send_post(text=post_text)
                    time.sleep(random.randint(30, 90))

                # 成功時はretryリセット
                site_state["entries"][entry_key] = {
                    "status": "success",
                    "retry_count": 0,
                    "posted_at": isoformat(now)
                }

            except Exception:
                retry_count = site_state["entries"].get(entry_key, {}).get("retry_count", 0) + 1

                if retry_count <= RETRY_LIMIT:
                    site_state.setdefault("retry_ids", []).append(entry_key)

                site_state["entries"][entry_key] = {
                    "status": "failed",
                    "retry_count": retry_count,
                    "last_tried_at": isoformat(now)
                }

        # 正常終了時のみ更新
        site_state["last_checked_at"] = isoformat(now)

    if MODE == "prod":
        save_state(state)


if __name__ == "__main__":
    main()
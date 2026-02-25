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
# ★ 今回の反映ポイント ★
# Gemini 429（レートリミット）検出専用の軽量例外
#
# 目的:
# - 429 が出た瞬間に「そのサイト単位で処理を止める」
# - last_checked_at を更新せず、次回同じ地点から再開する
# =========================================================
class GeminiRateLimitError(Exception):
    pass

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
def normalize_site_state(site_key, raw_state, now, mode):
    """
    - list形式だった posted_ids を dict に変換
    - last_checked_at が未設定の場合は初期値 None
    - モードによってログだけにする場合あり
    """
    migrated = False
    if raw_state is None:
        return {"last_checked_at": None, "posted_ids": {}}, False

    if isinstance(raw_state, list):
        logging.info(
            f"Migrate state [{site_key}]: list → dict"
            + (" (TEST: not saved)" if mode == "test" else "")
        )
        return {"last_checked_at": None, "posted_ids": {cid: isoformat(now) for cid in raw_state}}, True

    posted = raw_state.get("posted_ids")
    if isinstance(posted, list):
        raw_state["posted_ids"] = {cid: isoformat(now) for cid in posted}
        migrated = True

    raw_state.setdefault("posted_ids", {})
    return raw_state, migrated

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
        return f"{summary_text}\n{cve_line}"

    return summary_text

# =========================================================
# Gemini 要約
# =========================================================
def summarize(text, api_key, site_type=None):
    """
    Gemini 要約処理

    ★ 今回の反映ポイント（案A + 案B + 案C）
    - 案A: 呼び出し前にランダムジッターを入れて 429 回避
    - 案B: 503 の場合のみ 1 回だけリトライ
    - ★ 429 は即例外送出（サイト単位で処理を止めるため）
    - 案C: 429 以外の失敗時のみフォールバック文言
    """

    client = genai.Client(api_key=api_key)

    prompt = (
        """
以下の観点を必ず含め、日本語80文字以内で要約してください。

- 脆弱性の内容
- 影響を受ける対象
- 攻撃者が可能になる行為

注意:
- CVE番号は含めない
- 不明点は「可能性がある」と表現
- 事実のみ
"""
        if site_type in ("nvd_api", "jvn")
        else """
以下を日本語で簡潔に要約してください。
事実のみ。誇張なし。
80文字以内。
"""
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

            # ★ 429 は即サイト停止トリガー
            if "429" in msg:
                logging.error("Gemini summarize hit 429 (rate limit)")
                raise GeminiRateLimitError()

            # 503 のみ 1 回リトライ
            if attempt == 1 and "503" in msg:
                logging.warning("Gemini summarize retry due to 503")
                time.sleep(2)
                continue

            logging.error(f"Gemini summarize failed: {e}")
            break

    return "要約生成に失敗したため、脆弱性の存在のみ通知します。"

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

    original_state = load_state()
    state = json.loads(json.dumps(original_state))
    state_dirty = False

    now = utc_now()
    gemini_key = os.environ.get("GEMINI_API_KEY")

    if MODE == "prod":
        client = Client(base_url="https://bsky.social")
        client.login(
            os.environ.get("BLUESKY_IDENTIFIER"),
            os.environ.get("BLUESKY_PASSWORD")
        )

    for site_key, site in sites.items():
        if not site.get("enabled", False):
            continue

        logging.info(f"[{site_key}] ---")

        fetched_count = 0
        posted_count = 0
        cve_skip_count = 0
        first_skip = False

        # ★ サイト単位で 429 が出たかどうかのフラグ
        site_rate_limited = False

        site_state, migrated = normalize_site_state(site_key, state.get(site_key), now, MODE)
        state[site_key] = site_state
        if migrated and MODE == "prod":
            state_dirty = True

        last_checked = site_state.get("last_checked_at")

        if last_checked:
            since = parse_iso(last_checked)
        else:
            since = now - timedelta(days=1)
            first_skip = skip_first and MODE == "prod"

        until = now

        if site["type"] == "rss":
            items = fetch_rss(site, since, until)
        elif site["type"] == "nvd_api":
            items = fetch_nvd(site, since, until)
        elif site["type"] in ("jvn", "jvn_rss"):
            items = fetch_jvn(site, since, until)
        else:
            continue

        fetched_count = len(items)

        if first_skip:
            logging.info(f"[{site_key}] 初回実行のため既存記事 {fetched_count} 件をスキップ")
        else:
            for item in items:
                try:
                    cid = item.get("id")

                    if is_cve_already_posted(cid, site["type"], state):
                        cve_skip_count += 1
                        logging.info(f"[{site_key}] 既投稿 CVE スキップ: {cid}")
                        continue

                    trimmed = body_trim(item["text"], site_type=site["type"])
                    summary = trimmed[:SUMMARY_HARD_LIMIT] if force_test else summarize(
                        trimmed, gemini_key, site["type"]
                    )
                    post_text = format_post(site, summary, item)

                    if MODE == "test":
                        logging.info("[TEST]\n" + post_text + f"\nEmbed URL: {item['url']}")
                    else:
                        post_bluesky(client, post_text, item["url"])
                        time.sleep(random.randint(30, 90))

                    posted_count += 1

                    if cid and site["type"] != "rss":
                        state.setdefault("nvd", {}).setdefault("posted_ids", {})[cid] = isoformat(now)
                        logging.info(f"posted_id 追加: {cid}")
                        pruned = prune_posted_ids(state["nvd"]["posted_ids"], now)
                        if pruned > 0:
                            logging.info(f"Pruned {pruned} old posted_ids")

                except GeminiRateLimitError:
                    # ★ 429 発生時：
                    # - そのサイトの処理を即中断
                    # - last_checked_at を更新しない
                    logging.error(f"[{site_key}] Gemini 429 detected, stop processing this site")
                    site_rate_limited = True
                    break

        if site_rate_limited:
            logging.warning(f"[{site_key}] last_checked_at not updated due to rate limit")
            continue

        site_state["last_checked_at"] = isoformat(now)
        state_dirty = True

    if MODE == "prod" and state_dirty:
        save_state(state)

if __name__ == "__main__":
    main()
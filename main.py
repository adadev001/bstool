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
SITES_FILE = "sites.yaml"
STATE_FILE = "processed_urls.json"
MAX_POST_LENGTH = 140
SUMMARY_HARD_LIMIT = 100
POSTED_ID_RETENTION_DAYS = 30
POSTED_ID_MAX = 1000
RETRY_LIMIT = 3
GEMINI_RETRY_MAX = 2                  # Gemini失敗によるfallback→retry の上限回数

# =========================================================
# 時刻ユーティリティ
# =========================================================
def utc_now():
    return datetime.now(timezone.utc)

def isoformat(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_iso(ts: str) -> datetime:
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
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

# =========================================================
# state 正規化（後方互換対応）
# =========================================================
def normalize_site_state(site_key, raw_state, now, mode):
    if raw_state is None:
        return {
            "last_checked_at": None,
            "posted_ids": {},
            "retry_ids": [],
            "entries": {},
            "known_cves": []
        }, False

    if isinstance(raw_state, list):
        return {
            "last_checked_at": None,
            "posted_ids": {cid: isoformat(now) for cid in raw_state},
            "retry_ids": [],
            "entries": {},
            "known_cves": []
        }, True

    migrated = False
    posted = raw_state.get("posted_ids")
    if isinstance(posted, list):
        raw_state["posted_ids"] = {cid: isoformat(now) for cid in posted}
        migrated = True

    raw_state.setdefault("posted_ids", {})
    raw_state.setdefault("retry_ids", [])
    raw_state.setdefault("entries", {})
    raw_state.setdefault("known_cves", [])
    return raw_state, migrated

def prune_posted_ids(posted_ids: dict, now: datetime):
    before = len(posted_ids)
    cutoff = now - timedelta(days=POSTED_ID_RETENTION_DAYS)
    expired = [cid for cid, ts in posted_ids.items() if parse_iso(ts) < cutoff]
    for cid in expired:
        del posted_ids[cid]
    if len(posted_ids) > POSTED_ID_MAX:
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
# CVE 既投稿チェック（CVE横断重複対応）
# =========================================================
def is_cve_already_posted(cid, site_type, state):
    if not cid or site_type == "rss":
        return False
    # 全サイトの known_cves を横断して確認（NVD/JVN/JVD いずれが先行投稿しても重複防止）
    for site_state in state.values():
        if isinstance(site_state, dict) and cid in site_state.get("known_cves", []):
            return True
    return False

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
    client = genai.Client(api_key=api_key)
    prompt = (
        """
以下の観点がある場合には必ず含めてください。
ない場合には記事内容の事実のみを日本語95文字以内で要約してください。

- 対象の製品（アプリ）名とバージョン
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
以下の観点を必ず含め、日本語95文字以内で要約してください。

- 対象の製品（アプリ）名とバージョン
- 脆弱性の内容
- 影響を受ける対象
- 攻撃者が可能になる行為
- 事実のみ、誇張なし
"""
# 20260307 NVDの要約条件修正
# 以下を日本語で簡潔に要約してください。
# 事実のみ。誇張なし。
# 80文字以内。
# """
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

    # ★ None を返すことで呼び出し側が fallback と判断できる
    return None


# =========================================================
# データ取得（RSS / NVD / JVN）
# =========================================================
def fetch_rss(site, since=None, until=None):
    feed = feedparser.parse(site["url"])
    items = []
    for entry in feed.entries[: site.get("max_items", 1)]:
        published = entry.get("published_parsed")
        if published and since and until:
            entry_time = datetime.fromtimestamp(time.mktime(published), tz=timezone.utc)
            if not (since < entry_time <= until):
                continue
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
    if resp.status_code == 429:
        # ★ 例外を投げて呼び出し側でサイトレベルの失敗として扱う
        raise RuntimeError("NVD API rate limited (429)")
    resp.raise_for_status()
    data = resp.json()
    threshold = float(site.get("cvss_threshold", 0))
    items = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cid = cve.get("id")
        metrics = cve.get("metrics", {})
        score = 0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                score = float(metrics[key][0]["cvssData"]["baseScore"])
                break
        if not cid or score < threshold:
            continue
        desc = cve.get("descriptions", [{}])[0].get("value", "")
        items.append({
            "id": cid,
            "score": score,
            "text": desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}"
        })
    return items

def fetch_jvn(site, since, until):
    feed = feedparser.parse(site["url"])
    items = []
    for entry in feed.entries:
        if not entry.get("published_parsed"):
            continue
        entry_time = datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)
        if not (since < entry_time <= until):
            continue
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
# retry 用：記事単体の再取得
# =========================================================
def fetch_item_for_retry(entry_key, site, site_state):
    site_type = site["type"]

    # --- RSS：フィードを再パースして URL で突合 ---
    if site_type == "rss":
        try:
            url = entry_key  # entry_key = 記事URL
            feed = feedparser.parse(site["url"])
            for entry in feed.entries:
                if entry.get("link") == url:
                    return {
                        "id": url,
                        "text": f"{entry.get('title', '')}\n{entry.get('summary', '')}",
                        "url": url,
                    }
            logging.warning(f"retry fetch (rss): {url} not found in feed")
            return None
        except Exception as e:
            logging.warning(f"retry fetch (rss) failed for {entry_key}: {e}")
            return None

    # --- NVD：CVE ID 単体で API 問い合わせ ---
    elif site_type == "nvd_api":
        try:
            cve_id = entry_key
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                timeout=30
            )
            if resp.status_code == 429:
                logging.warning(f"NVD API 429 on retry fetch for {cve_id}")
                return None
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            if not vulns:
                return None
            cve = vulns[0].get("cve", {})
            metrics = cve.get("metrics", {})
            score = 0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    score = float(metrics[key][0]["cvssData"]["baseScore"])
                    break
            desc = cve.get("descriptions", [{}])[0].get("value", "")
            return {
                "id": cve_id,
                "score": score,
                "text": desc,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            }
        except Exception as e:
            logging.warning(f"retry fetch (nvd) failed for {entry_key}: {e}")
            return None

    # --- JVN：RSS を再パースして CVE ID で突合 ---
    elif site_type in ("jvn", "jvn_rss"):
        try:
            cve_id = entry_key
            feed = feedparser.parse(site["url"])
            for entry in feed.entries:
                cve_ids = [t.get("term") for t in entry.get("tags", []) if t.get("term", "").startswith("CVE-")]
                if cve_id in cve_ids:
                    return {
                        "id": cve_id,
                        "score": site.get("default_cvss", 0),
                        "text": entry.get("summary", ""),
                        "url": entry.get("link")
                    }
            logging.warning(f"retry fetch (jvn): {cve_id} not found in feed")
            return None
        except Exception as e:
            logging.warning(f"retry fetch (jvn) failed for {entry_key}: {e}")
            return None

    return None

# =========================================================
# Bluesky 投稿
# =========================================================
def post_bluesky(client, text, url):
    """
    embed付き投稿を試みる。
    embed生成失敗時はテキスト投稿にフォールバック。
    テキスト投稿も失敗した場合は例外を外に伝播させる（retry対象にするため）。
    """
    try:
        resp = requests.get("https://cardyb.bsky.app/v1/extract", params={"url": url}, timeout=10)
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

    except Exception as embed_err:
        # embed失敗 → テキスト投稿にフォールバック
        # ★ ここでの例外は飲み込む（embedの失敗はretry不要）
        logging.warning(f"Embed failed, fallback to text post: {embed_err}")
        # ★ テキスト投稿が失敗した場合は例外を外に伝播させ、retry_ids に登録させる
        client.send_post(text=text + f"\n{url}")

# =========================================================
# 記事1件を処理する共通関数（通常 / retry 共用）
# =========================================================
def process_item(item, site, site_state, state, now, MODE, force_test, gemini_key, bsky_client, is_retry=False):
    """
    Returns:
        "success" | "failed" | "skipped"
    """
    cid = item.get("id")
    entry_key = cid or item.get("url")
    label = "[再投稿]" if is_retry else ""

    # CVE横断重複チェック
    if site["type"] in ("nvd_api", "jvn") and is_cve_already_posted(cid, site["type"], state):
        logging.info(f"[{site['type']}] {cid} は既投稿のためスキップ (known_cve)")
        site_state["entries"].setdefault(entry_key, {}).update({
            "status": "skipped",
            "last_tried_at": isoformat(now),
            "reason": "known_cve",
        })
        # CVE横断重複スキップ：NVD/JVN間の重複判定によるスキップ。
        # このケースでは retry_ids に登録されていないが、
        # 万一 retry_ids に残っていた場合は除去して再試行を止める。
        if entry_key in site_state.get("retry_ids", []):
            site_state["retry_ids"].remove(entry_key)
        return "skipped"

    # 本文処理
    original_text = item.get("text", "")
    trimmed = body_trim(original_text, site_type=site["type"])
    post_url = item.get("url", "")

    if force_test:
        summary = trimmed[:SUMMARY_HARD_LIMIT]
        gemini_failed = False
    else:
        summary = summarize(trimmed, gemini_key, site["type"])
        gemini_failed = (summary is None)
        if gemini_failed:
            # ★ Gemini失敗（429/503等）→ フォールバック文字列で即投稿
            #    その後、retry_count < GEMINI_RETRY_MAX なら retry_ids に登録して次回再要約・再投稿
            summary = "要約生成に失敗したため、脆弱性の存在のみ通知します。"
            logging.warning(f"[{site.get('display_name', site['type'])}] Gemini要約失敗、フォールバック投稿: {entry_key}")

    post_text = format_post(site, summary, item)

    try:
        if MODE == "test":
            logging.info(f"[TEST]{label}\n{post_text}")
        else:
            post_bluesky(bsky_client, post_text, post_url)
            time.sleep(random.randint(30, 90))

        # --- 投稿成功 ---
        current_retry_count = site_state["entries"].get(entry_key, {}).get("retry_count", 0)

        if gemini_failed:
            # フォールバック投稿成功：retry_count < GEMINI_RETRY_MAX なら retry_ids に登録して次回再要約
            new_retry_count = current_retry_count + 1
            final_status = "fallback"
            if new_retry_count <= GEMINI_RETRY_MAX:
                logging.info(f"[{site.get('display_name', site['type'])}] フォールバック投稿成功、次回再要約登録 (retry_count={new_retry_count}): {entry_key}")
                if entry_key not in set(site_state.get("retry_ids", [])):
                    site_state.setdefault("retry_ids", []).append(entry_key)
            else:
                logging.info(f"[{site.get('display_name', site['type'])}] retry上限到達、retry_ids登録なし: {entry_key}")
        else:
            # 通常要約投稿成功（またはretryで要約成功）
            new_retry_count = current_retry_count
            final_status = "success"
            # retry_ids から除去（要約成功で完了）
            if entry_key in site_state.get("retry_ids", []):
                site_state["retry_ids"].remove(entry_key)

        entry = site_state["entries"].setdefault(entry_key, {})
        # original_text は保存しない（retry時はソースから再取得する）
        entry.update({
            "status": final_status,
            "first_seen_at": entry.get("first_seen_at", isoformat(now)),
            "last_tried_at": isoformat(now),
            "reason": "gemini_failed" if gemini_failed else "",
            "retry_count": new_retry_count,
            "posted_at": isoformat(now),
            "url": post_url,
            "score": item.get("score", 0),
        })

        if site["type"] in ("nvd_api", "jvn") and cid and not gemini_failed:
            # 要約あり投稿成功時のみ known_cves に登録
            # （fallback投稿では次回再投稿するため、まだ完了扱いにしない）
            if cid not in site_state.get("known_cves", []):
                site_state.setdefault("known_cves", []).append(cid)
            site_state["posted_ids"][cid] = isoformat(now)
            pruned = prune_posted_ids(site_state["posted_ids"], now)
            if pruned > 0:
                logging.info(f"posted_ids prune: {pruned} 件削除 ({site_key})")

        log_label = "[フォールバック]" if gemini_failed else ""
        logging.info(f"[{site.get('display_name', site['type'])}]{label}{log_label} 投稿成功: {entry_key}")
        return "success"

    except Exception as e:
        # --- 失敗 ---
        retry_count = site_state["entries"].get(entry_key, {}).get("retry_count", 0) + 1
        logging.warning(f"[{site.get('display_name', site['type'])}]{label} 投稿失敗 (retry_count={retry_count}): {e}")

        site_state["entries"].setdefault(entry_key, {}).update({
            "status": "failed",
            "first_seen_at": site_state["entries"].get(entry_key, {}).get("first_seen_at", isoformat(now)),
            "last_tried_at": isoformat(now),
            "reason": str(e),
            "retry_count": retry_count,
            "posted_at": None,
            # original_text は保存しない（retry時はソースから再取得する）
            "url": post_url,
            "score": item.get("score", 0),
        })

        # retry_ids に追加（重複防止）
        existing_retries = set(site_state.get("retry_ids", []))
        if entry_key not in existing_retries:
            site_state.setdefault("retry_ids", []).append(entry_key)

        return "failed"

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

    bsky_client = None
    if MODE == "prod":
        bsky_client = Client(base_url="https://bsky.social")
        bsky_client.login(
            os.environ.get("BLUESKY_IDENTIFIER"),
            os.environ.get("BLUESKY_PASSWORD")
        )

    for site_key, site in sites.items():
        if not site.get("enabled", False):
            continue

        logging.info(f"[{site_key}] ---")

        fetched_count = 0
        posted_count = 0
        retry_posted_count = 0
        cve_skip_count = 0
        fail_count = 0
        first_skip = False

        # === state 正規化 ===
        site_state, migrated = normalize_site_state(site_key, state.get(site_key), now, MODE)
        state[site_key] = site_state
        if migrated:
            if MODE == "prod":
                logging.info(f"Migrate state for {site_key} (prod)")
                state_dirty = True
            else:
                logging.info(f"Migrate state for {site_key} (TEST: not saved)")

        last_checked = site_state.get("last_checked_at")
        if last_checked:
            since = parse_iso(last_checked)
        else:
            since = now - timedelta(days=1)
            first_skip = skip_first and MODE == "prod"

        until = now

        # =========================================================
        # ★ STEP 1: retry_ids の再試行（先に処理）
        # =========================================================
        retry_ids_snapshot = list(site_state.get("retry_ids", []))[:RETRY_LIMIT]
        if retry_ids_snapshot:
            logging.info(f"[{site_key}] retry_ids 再試行: {len(retry_ids_snapshot)} 件")

        for entry_key in retry_ids_snapshot:
            # ★ original_text は保持せず、ソース種別ごとに再取得する
            retry_item = fetch_item_for_retry(entry_key, site, site_state)
            if retry_item is None:
                logging.warning(f"[{site_key}] retry再取得失敗: {entry_key}、次回に持ち越し")
                continue

            result = process_item(
                item=retry_item,
                site=site,
                site_state=site_state,
                state=state,
                now=now,
                MODE=MODE,
                force_test=force_test,
                gemini_key=gemini_key,
                bsky_client=bsky_client,
                is_retry=True,
            )

            # retry_ids の除去は process_item 内で完結している
            # ここではカウントのみ管理する
            if result == "success":
                retry_posted_count += 1
            # "failed" は retry_ids に残したまま（次回再試行）
            # "skipped" は process_item 内で retry_ids から除去済み

        # =========================================================
        # ★ STEP 2: 通常記事の取得・処理
        # =========================================================
        try:
            if site["type"] == "rss":
                items = fetch_rss(site, since, until)
            elif site["type"] == "nvd_api":
                items = fetch_nvd(site, since, until)
            elif site["type"] in ("jvn", "jvn_rss"):
                items = fetch_jvn(site, since, until)
            else:
                continue
        except RuntimeError as fetch_err:
            # NVD 429 等、記事取得レベルの失敗
            # ★ last_checked_at を進めない（次回同じ時間窓を再取得）
            # ★ retry_ids の処理結果（STEP 1）は保存する
            logging.warning(f"[{site_key}] 記事取得失敗のため通常処理をスキップ: {fetch_err}")
            logging.info(f"[{site_key}] fetched=0, posted=0, retry_posted={retry_posted_count}, skipped=0, failed=0, retry_pending={len(site_state.get('retry_ids', []))}")
            state_dirty = True  # STEP 1 の retry 処理結果を保存するため
            continue

        fetched_count = len(items)

        if first_skip:
            logging.info(f"[{site_key}] 初回実行のため既存記事 {fetched_count} 件をスキップ")
        else:
            for item in items:
                cid = item.get("id")
                entry_key = cid or item.get("url")

                # 成功済み・fallback済み（retry_ids で管理中）はスキップ
                existing_entry = site_state.get("entries", {}).get(entry_key, {})
                if existing_entry.get("status") in ("success", "fallback"):
                    continue

                result = process_item(
                    item=item,
                    site=site,
                    site_state=site_state,
                    state=state,
                    now=now,
                    MODE=MODE,
                    force_test=force_test,
                    gemini_key=gemini_key,
                    bsky_client=bsky_client,
                    is_retry=False,
                )

                if result == "success":
                    posted_count += 1
                elif result == "skipped":
                    cve_skip_count += 1
                elif result == "failed":
                    fail_count += 1

        site_state["last_checked_at"] = isoformat(now)
        state_dirty = True

        # サイト単位サマリログ
        logging.info(
            f"[{site_key}] fetched={fetched_count}, posted={posted_count}, "
            f"retry_posted={retry_posted_count}, skipped={cve_skip_count}, "
            f"failed={fail_count}, retry_pending={len(site_state.get('retry_ids', []))}"
        )

    if MODE == "prod" and state_dirty:
        save_state(state)


if __name__ == "__main__":
    main()

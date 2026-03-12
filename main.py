"""
main.py - News to Bluesky Bot
==============================
各種ニュースサイト（RSS / NVD API / JVN）から記事・脆弱性情報を取得し、
Gemini で日本語要約したうえで Bluesky に自動投稿するボット。

処理の大まかな流れ:
  1. sites.yaml から監視対象サイト一覧を読み込む
  2. processed_urls.json（state）から前回の処理状況を復元する
  3. Bluesky にログイン（prod モード時のみ）
  4. サイトごとに以下を実行:
     a. 前回失敗した記事（retry_ids）を再試行
     b. 新着記事を取得して Gemini 要約 → Bluesky 投稿
  5. 処理結果を state に保存する
"""

import os
import json
import requests
import yaml
import feedparser
import logging
import time
import random
import httpx
from google import genai
from atproto import Client, models
from atproto_client.exceptions import InvokeTimeoutError
from datetime import datetime, timedelta, timezone

# =========================================================
# 定数定義
# =========================================================

SITES_FILE = "sites.yaml"           # 監視サイト設定ファイル
STATE_FILE = "processed_urls.json"  # 処理済み記事の状態管理ファイル

MAX_POST_LENGTH = 140        # Bluesky 投稿の最大文字数
SUMMARY_HARD_LIMIT = 100     # Gemini 要約文の上限文字数（これを超えた場合は末尾を「…」で切る）

POSTED_ID_RETENTION_DAYS = 30  # 投稿済み ID を state に保持する日数
POSTED_ID_MAX = 1000            # state に保持する投稿済み ID の最大件数（超えたら古い順に削除）

RETRY_LIMIT = 3       # 1回の実行で再試行する記事の上限件数
GEMINI_RETRY_MAX = 2  # Gemini 失敗時にフォールバック投稿→再要約を試みる最大回数


# =========================================================
# 時刻ユーティリティ
# =========================================================

def utc_now():
    """現在時刻を UTC タイムゾーン付きで返す。"""
    return datetime.now(timezone.utc)

def isoformat(dt: datetime) -> str:
    """datetime を ISO 8601 形式（ミリ秒付き・末尾Z）の文字列に変換する。
    例: 2025-03-01T12:00:00.000Z
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_iso(ts: str) -> datetime:
    """ISO 8601 形式の文字列を datetime（UTC）に変換する。
    末尾の "Z" を "+00:00" に置換して fromisoformat に渡す。
    """
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# =========================================================
# 設定 / state 読み込み・保存
# =========================================================

def load_config():
    """sites.yaml を読み込んで辞書として返す。
    サイト一覧・動作モード・各種設定が含まれる。
    """
    with open(SITES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_state():
    """processed_urls.json から前回実行時の処理状況を読み込む。
    ファイルが存在しない or 破損している場合は空の辞書を返す。
    """
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_state(state):
    """処理状況を processed_urls.json に書き出す。
    prod モードかつ state に変更があった場合のみ呼び出される。
    """
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


# =========================================================
# state 正規化（後方互換対応）
# =========================================================

def normalize_site_state(site_key, raw_state, now, mode):
    """過去バージョンの state フォーマットを現行フォーマットに変換する。

    バージョン間で state の構造が変わった場合でも動作を継続できるよう、
    古い形式（例: posted_ids がリスト）を検出して辞書形式に変換する。

    Returns:
        (site_state: dict, migrated: bool)
        migrated=True の場合は state を保存し直す必要がある。
    """
    # state が存在しない（初回実行）場合は初期構造を返す
    if raw_state is None:
        return {
            "last_checked_at": None,   # 前回チェック日時（この時刻以降の記事のみ取得）
            "posted_ids": {},          # 投稿済み CVE ID → 投稿日時 の辞書
            "retry_ids": [],           # 再試行待ち記事の ID リスト
            "entries": {},             # 記事ごとの詳細ステータス
            "known_cves": []           # 投稿完了済み CVE ID の一覧（NVD/JVN 横断重複防止用）
        }, False

    # 旧バージョン: posted_ids がリスト形式だった場合
    if isinstance(raw_state, list):
        # リスト → 辞書（全件を現在時刻で登録）に変換
        return {
            "last_checked_at": None,
            "posted_ids": {cid: isoformat(now) for cid in raw_state},
            "retry_ids": [],
            "entries": {},
            "known_cves": []
        }, True

    # posted_ids だけリスト形式で残っている場合の部分移行
    migrated = False
    posted = raw_state.get("posted_ids")
    if isinstance(posted, list):
        raw_state["posted_ids"] = {cid: isoformat(now) for cid in posted}
        migrated = True

    # 新しいキーが存在しない場合はデフォルト値を補完（キーの追加に対する後方互換）
    raw_state.setdefault("posted_ids", {})
    raw_state.setdefault("retry_ids", [])
    raw_state.setdefault("entries", {})
    raw_state.setdefault("known_cves", [])
    return raw_state, migrated

def prune_posted_ids(posted_ids: dict, now: datetime):
    """posted_ids から古いエントリを削除してメモリ・ファイルサイズを抑える。

    削除条件（どちらか該当すれば削除）:
      1. 投稿日時が POSTED_ID_RETENTION_DAYS 日より古い
      2. 件数が POSTED_ID_MAX を超えている（古い順に削除）

    Returns:
        削除した件数（ログ出力用）
    """
    before = len(posted_ids)

    # 条件1: 保持期限切れのエントリを削除
    cutoff = now - timedelta(days=POSTED_ID_RETENTION_DAYS)
    expired = [cid for cid, ts in posted_ids.items() if parse_iso(ts) < cutoff]
    for cid in expired:
        del posted_ids[cid]

    # 条件2: 上限件数を超えた場合、古い順に超過分を削除
    if len(posted_ids) > POSTED_ID_MAX:
        sorted_items = sorted(posted_ids.items(), key=lambda x: parse_iso(x[1]))
        for cid, _ in sorted_items[:-POSTED_ID_MAX]:
            del posted_ids[cid]

    return before - len(posted_ids)


# =========================================================
# 共通ユーティリティ
# =========================================================

def cvss_to_severity(score: float) -> str:
    """CVSS スコアを深刻度ラベルに変換する。
    CVSS v3 の基準に準拠:
      9.0以上 → CRITICAL / 7.0以上 → HIGH / 4.0以上 → MEDIUM / それ以下 → LOW
    """
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

def safe_truncate(text: str, limit: int) -> str:
    """文字数が limit を超える場合、limit-1 文字で切って末尾に「…」を付ける。
    Bluesky の文字数制限や Gemini 要約の上限に合わせるために使用。
    """
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


# =========================================================
# 本文前処理
# =========================================================

def body_trim(text, max_len=2500, site_type=None):
    """Gemini に渡す前に記事本文を前処理して不要な行を取り除く。

    NVD / JVN の場合:
      脆弱性の説明に関連するキーワード（allow, attack 等）を含む行のみ抽出する。
      CVE の説明文はボイラープレートが多いため、関連行だけ送ることでトークン数を削減。

    RSS（通常記事）の場合:
      空行・短すぎる行（10文字以下）を除去し、先頭 6 行だけ使う。
      フィードの HTML タグ残留や広告文を排除する効果もある。
    """
    if site_type in ("nvd_api", "jvn"):
        # 脆弱性関連キーワードを含む行のみ抽出
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

    # RSS: 短すぎる行を除いた先頭 6 行を使用
    lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 10]
    return "\n".join(lines[:6])[:max_len]


# =========================================================
# CVE 既投稿チェック（NVD / JVN 横断重複防止）
# =========================================================

def is_cve_already_posted(cid, site_type, state):
    """同一 CVE が複数ソース（NVD・JVN 等）に存在する場合の重複投稿を防ぐ。

    NVD と JVN は同じ CVE を別々に掲載するため、
    いずれかのサイトで投稿済みの CVE ID は全サイトの known_cves を横断して確認する。
    RSS 記事はこのチェックの対象外（CVE ID を持たないため）。
    """
    # RSS は CVE ID ベースの重複チェック対象外
    if not cid or site_type == "rss":
        return False

    # 全サイトの known_cves を横断確認
    for site_state in state.values():
        if isinstance(site_state, dict) and cid in site_state.get("known_cves", []):
            return True
    return False


# =========================================================
# 投稿文生成
# =========================================================

def format_post(site, summary, item):
    """Bluesky に投稿するテキストを組み立てる。

    NVD / JVN の場合:
      要約文 + 改行 + CVE ID と CVSS スコア・深刻度の行を付加する。
      例:
        Apache HTTP Server 2.4.x に XSS 脆弱性。攻撃者がスクリプトを実行可能。
        CVE-2024-XXXX CVSS 7.5 | HIGH

    RSS（通常記事）の場合:
      要約文のみ（URL は embed カードとして別途添付される）。
    """
    # 要約文が MAX_POST_LENGTH を超える場合は切り捨て、改行はスペースに変換
    summary_text = safe_truncate(summary.replace("\n", " "), MAX_POST_LENGTH)

    if site["type"] in ("nvd_api", "jvn"):
        score = item.get("score", 0)
        severity = cvss_to_severity(score)
        cve_line = f"{item['id']} CVSS {score} | {severity}"
        return f"{summary_text}\n{cve_line}"

    return summary_text


# =========================================================
# Gemini クライアント（使い回し用シングルトン）
# =========================================================

# モジュール内でひとつだけ保持するクライアントインスタンス。
# 記事ごとに Client() を生成すると接続オーバーヘッドが生じるため、
# 初回呼び出し時に生成し、以降は使い回す（シングルトンパターン）。
_gemini_client = None

def get_gemini_client(api_key):
    """Gemini クライアントを取得する。未生成なら生成して返す。"""
    global _gemini_client
    if _gemini_client is None:
        _gemini_client = genai.Client(api_key=api_key)
    return _gemini_client


# =========================================================
# Gemini 要約
# =========================================================

# 試行するモデルの優先順位リスト。
# gemini-2.5-flash-lite が 429 / 全試行失敗になった場合、
# gemini-2.5-flash にフォールバックする。
# 各モデルは独立したレート制限枠を持つため、片方が枯渇しても続行できる。
# ※ gemini-2.0-flash は 2026年6月1日に廃止予定のため使用しない。
GEMINI_MODELS = ["gemini-2.5-flash-lite", "gemini-2.5-flash"]

# 429 / 503（レート制限・過負荷）発生時の指数バックオフ待機秒数。
# attempt 2回目以降: 5秒 → 15秒 → 30秒 → 60秒 と段階的に増加させ、
# API の制限解除を待ちながら再試行する。
GEMINI_BACKOFF = [5, 15, 30, 60]

# 1モデルあたりの最大試行回数
GEMINI_MAX_ATTEMPTS = 4

def summarize(text, api_key, site_type=None):
    """記事本文を Gemini で日本語要約する。

    処理の流れ:
      1. モデルリストの先頭（lite）から試行開始
      2. 失敗が 429/503 の場合: 指数バックオフで待機 → 同モデルで再試行
      3. GEMINI_MAX_ATTEMPTS 回失敗した場合: 次のモデルへフォールバック
      4. それ以外のエラー（認証エラー等）: 即座に次のモデルへ
      5. 全モデル・全試行が失敗した場合: None を返す（呼び出し側がフォールバック処理）

    Args:
        text: 要約対象の本文（body_trim 済みのもの）
        api_key: Gemini API キー
        site_type: サイト種別。"nvd_api" / "jvn" の場合は脆弱性向けプロンプトを使用

    Returns:
        要約文字列（SUMMARY_HARD_LIMIT 文字以内）、または None（全試行失敗時）
    """
    client = get_gemini_client(api_key)

    # サイト種別に応じてプロンプトを切り替え
    prompt = (
        # NVD / JVN 向け: 情報が不足していても事実のみ記述、CVE番号は除外
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
        # RSS 向け: 4観点を必ず含める
        else """
以下の観点を必ず含め、日本語95文字以内で要約してください。

- 対象の製品（アプリ）名とバージョン
- 脆弱性の内容
- 影響を受ける対象
- 攻撃者が可能になる行為
- 事実のみ、誇張なし
"""
    ) + f"\n{text}"

    # モデルをまたいで最大 GEMINI_MAX_ATTEMPTS 回試みる
    attempt = 0
    for model in GEMINI_MODELS:
        while attempt < GEMINI_MAX_ATTEMPTS:
            attempt += 1

            # 1回目は短いランダム待機（API への急激な集中を避ける）
            # 2回目以降はバックオフテーブルに従って待機秒数を増加
            wait = random.uniform(1.0, 2.0) if attempt == 1 else GEMINI_BACKOFF[min(attempt - 2, len(GEMINI_BACKOFF) - 1)]
            time.sleep(wait)

            try:
                resp = client.models.generate_content(
                    model=model,
                    contents=prompt
                )
                result = safe_truncate(resp.text.strip(), SUMMARY_HARD_LIMIT)

                # リトライが発生していた場合はログに残す
                if attempt > 1 or model != GEMINI_MODELS[0]:
                    logging.info(f"Gemini summarize success (model={model}, attempt={attempt})")
                return result

            except Exception as e:
                msg = str(e)
                error_type = type(e).__name__

                # エラー種別を分類してログに残す（原因調査用）
                # - RATE_LIMIT: 429/503/quota → リトライで回復が見込める
                # - OTHER: 認証エラー・不正リクエスト等 → リトライ不要
                is_rate_limit = "429" in msg or "503" in msg or "quota" in msg.lower() or "resource_exhausted" in msg.lower()

                if is_rate_limit:
                    # レート制限: バックオフ後に同モデルで再試行
                    logging.warning(
                        f"Gemini {model} RATE_LIMIT "
                        f"(attempt={attempt}/{GEMINI_MAX_ATTEMPTS}, wait={wait:.1f}s) "
                        f"[{error_type}] {msg[:200]}"  # メッセージが長い場合は先頭200文字のみ
                    )
                    if attempt >= GEMINI_MAX_ATTEMPTS:
                        # このモデルの試行上限に達した → 次のモデルへ
                        logging.warning(f"Gemini {model} 全試行失敗、次モデルへフォールバック")
                        break
                    continue  # 同モデルで再試行
                else:
                    # レート制限以外のエラー（認証失敗・不正なリクエスト等）は即座に次モデルへ
                    logging.error(
                        f"Gemini {model} OTHER_ERROR "
                        f"(attempt={attempt}) "
                        f"[{error_type}] {msg[:200]}"
                    )
                    break

    # 全モデル・全試行失敗 → None を返して呼び出し側でフォールバック処理させる
    logging.error("Gemini summarize: 全モデル・全試行失敗")
    return None


# =========================================================
# データ取得（RSS / NVD API / JVN）
# =========================================================

def fetch_rss(site, since=None, until=None):
    """RSS フィードから新着記事を取得する。

    since〜until の時間窓に含まれる記事のみ返す。
    max_items で取得上限を設定（未指定時は 1 件）。

    Returns:
        記事の辞書リスト。各辞書は {id, text, url} を持つ。
    """
    feed = feedparser.parse(site["url"])
    items = []
    for entry in feed.entries[: site.get("max_items", 1)]:
        published = entry.get("published_parsed")
        if published and since and until:
            entry_time = datetime.fromtimestamp(time.mktime(published), tz=timezone.utc)
            # 時間窓外の記事はスキップ
            if not (since < entry_time <= until):
                continue
        items.append({
            "id": entry.get("link"),   # RSS ではリンク URL を ID として使用
            "text": f"{entry.get('title','')}\n{entry.get('summary','')}",
            "url": entry.get("link"),
        })
    return items

def fetch_nvd(site, start, end):
    """NVD（米国国家脆弱性データベース）API から CVE 情報を取得する。

    pubStartDate〜pubEndDate の範囲で公開された CVE を取得し、
    cvss_threshold 以上のスコアのものだけ返す。

    Raises:
        RuntimeError: 429（レート制限）の場合。呼び出し側でサイトごとスキップする。
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": site.get("max_items", 50),
        "pubStartDate": isoformat(start),
        "pubEndDate": isoformat(end),
    }
    resp = requests.get(url, params=params, timeout=30)

    # NVD は無料利用時にレート制限が厳しい。429 は次回実行に持ち越す
    if resp.status_code == 429:
        raise RuntimeError("NVD API rate limited (429)")
    resp.raise_for_status()

    data = resp.json()
    threshold = float(site.get("cvss_threshold", 0))
    items = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cid = cve.get("id")
        metrics = cve.get("metrics", {})

        # CVSS スコアは v3.1 → v3.0 → v2 の優先順位で取得
        score = 0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                score = float(metrics[key][0]["cvssData"]["baseScore"])
                break

        # CVE ID がない or スコアが閾値未満はスキップ
        if not cid or score < threshold:
            continue

        # 英語の説明文（descriptions の先頭）を本文として使用
        desc = cve.get("descriptions", [{}])[0].get("value", "")
        items.append({
            "id": cid,
            "score": score,
            "text": desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}"
        })
    return items

def fetch_jvn(site, since, until):
    """JVN（Japan Vulnerability Notes）の RSS フィードから CVE 情報を取得する。

    RSS エントリのタグから CVE ID を抽出し、since〜until の時間窓内のものだけ返す。
    CVE タグが付いていないエントリはスキップする（JVN 固有 ID のみの記事を除外）。

    Returns:
        記事の辞書リスト（max_items 件まで）
    """
    feed = feedparser.parse(site["url"])
    items = []
    for entry in feed.entries:
        # 公開日時のないエントリはスキップ
        if not entry.get("published_parsed"):
            continue

        entry_time = datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)
        if not (since < entry_time <= until):
            continue

        # エントリのタグから CVE ID（"CVE-" で始まるもの）を抽出
        cve_ids = [t for t in entry.get("tags", []) if t.get("term", "").startswith("CVE-")]
        if not cve_ids:
            continue  # CVE タグなしはスキップ

        # 複数の CVE が紐づく場合は先頭の CVE ID を代表として使用
        items.append({
            "id": cve_ids[0]["term"],
            "score": site.get("default_cvss", 0),  # JVN は CVSS スコアを API では返さないため設定値を使用
            "text": entry.get("summary", ""),
            "url": entry.get("link")
        })
    return items[: site.get("max_items", 1)]


# =========================================================
# retry 用：記事単体の再取得
# =========================================================

def fetch_item_for_retry(entry_key, site, site_state):
    """retry_ids に登録された記事を再取得する。

    通常の fetch_* 関数は時間窓で絞り込むため、retry 時には使えない。
    この関数はソース種別ごとに記事を ID で直接取得する。

    本文テキストは state に保存しない設計のため、
    retry 時には必ずソースから再取得する（データの鮮度を保つ）。

    Returns:
        記事辞書 {id, text, url, ...} または None（取得失敗時）
    """
    site_type = site["type"]

    # --- RSS: フィードを再パースして URL（entry_key）で突合 ---
    if site_type == "rss":
        try:
            url = entry_key  # RSS の entry_key は記事 URL
            feed = feedparser.parse(site["url"])
            for entry in feed.entries:
                if entry.get("link") == url:
                    return {
                        "id": url,
                        "text": f"{entry.get('title', '')}\n{entry.get('summary', '')}",
                        "url": url,
                    }
            # フィードから記事が消えていた場合（期限切れ等）
            logging.warning(f"retry fetch (rss): {url} not found in feed")
            return None
        except Exception as e:
            logging.warning(f"retry fetch (rss) failed for {entry_key}: {e}")
            return None

    # --- NVD: CVE ID を指定して API を直接叩く ---
    elif site_type == "nvd_api":
        try:
            cve_id = entry_key
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                timeout=30
            )
            if resp.status_code == 429:
                # レート制限中は次回に持ち越し
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

    # --- JVN: RSS を再パースして CVE ID で突合 ---
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

    # 未対応のサイト種別
    return None


# =========================================================
# Bluesky 投稿
# =========================================================

def post_bluesky(client, text, url):
    """Bluesky にリンクカード（embed）付きで投稿する。

    処理の流れ:
      1. cardyb.bsky.app で URL の OGP 情報（タイトル・説明・サムネイル）を取得
      2. サムネイル画像を Bluesky にアップロードして blob を取得
      3. embed オブジェクトを組み立てて投稿

    embed 生成・投稿が失敗した場合:
      テキスト + URL の文字列投稿にフォールバックする。
      テキスト投稿も失敗した場合は例外を呼び出し元に伝播させ、
      process_item 内で retry_ids に登録させる。

    サムネイル画像の条件:
      取得成功 かつ 1MB 未満の場合のみアップロード（大きすぎる画像は除外）。
    """
    try:
        # OGP 情報取得
        resp = requests.get("https://cardyb.bsky.app/v1/extract", params={"url": url}, timeout=10)
        card = resp.json()

        # サムネイル画像のアップロード（存在する場合のみ）
        image_blob = None
        image_url = card.get("image")
        if image_url:
            img = requests.get(image_url, timeout=10)
            if img.status_code == 200 and len(img.content) < 1_000_000:
                upload = client.upload_blob(img.content)
                image_blob = upload.blob

        # embed オブジェクトを組み立てて投稿
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
        # embed 付き投稿が失敗した場合はテキスト投稿にフォールバック
        # （embed の失敗自体は retry 不要なためここで飲み込む）
        logging.warning(f"Embed failed, fallback to text post: {embed_err}")
        # テキスト投稿が失敗した場合は例外を外に伝播させる（retry_ids 登録のため）
        client.send_post(text=text + f"\n{url}")


# =========================================================
# 記事1件を処理する共通関数（通常投稿 / retry 共用）
# =========================================================

def process_item(item, site, site_state, state, now, MODE, force_test, gemini_key, bsky_client, is_retry=False):
    """1件の記事を要約して Bluesky に投稿し、結果を state に記録する。

    通常投稿（STEP 2）とリトライ投稿（STEP 1）の両方で使用する共通関数。

    処理の流れ:
      1. CVE 横断重複チェック（NVD/JVN のみ）
      2. 本文を前処理（body_trim）
      3. Gemini で要約（force_test 時はスキップ）
      4. 投稿テキストを組み立て（format_post）
      5. Bluesky に投稿（test モード時はログ出力のみ）
      6. 成功/失敗に応じて state を更新

    Gemini 要約失敗時のフォールバック処理:
      「要約生成に失敗したため…」の固定文で投稿し、
      GEMINI_RETRY_MAX 回までは retry_ids に登録して次回再要約を試みる。

    Returns:
        "success" | "failed" | "skipped"
    """
    cid = item.get("id")
    entry_key = cid or item.get("url")  # CVE ID または URL を一意キーとして使用
    label = "[再投稿]" if is_retry else ""

    # --- 1. CVE 横断重複チェック ---
    # NVD と JVN は同じ CVE を掲載するため、どちらかで投稿済みならスキップ
    if site["type"] in ("nvd_api", "jvn") and is_cve_already_posted(cid, site["type"], state):
        logging.info(f"[{site['type']}] {cid} は既投稿のためスキップ (known_cve)")
        site_state["entries"].setdefault(entry_key, {}).update({
            "status": "skipped",
            "last_tried_at": isoformat(now),
            "reason": "known_cve",
        })
        # retry_ids に残っていた場合は除去（重複スキップなので再試行不要）
        if entry_key in site_state.get("retry_ids", []):
            site_state["retry_ids"].remove(entry_key)
        return "skipped"

    # --- 2. 本文前処理 ---
    original_text = item.get("text", "")
    trimmed = body_trim(original_text, site_type=site["type"])
    post_url = item.get("url", "")

    # --- 3. Gemini 要約 ---
    if force_test:
        # テスト用設定: Gemini API を呼ばず本文の先頭を使う
        summary = trimmed[:SUMMARY_HARD_LIMIT]
        gemini_failed = False
    else:
        summary = summarize(trimmed, gemini_key, site["type"])
        gemini_failed = (summary is None)
        if gemini_failed:
            # 全試行失敗時はフォールバック文で投稿し、次回再要約を試みる
            summary = "要約生成に失敗したため、脆弱性の存在のみ通知します。"
            logging.warning(f"[{site.get('display_name', site['type'])}] Gemini要約失敗、フォールバック投稿: {entry_key}")

    # --- 4. 投稿テキスト組み立て ---
    post_text = format_post(site, summary, item)

    # --- 5. Bluesky 投稿 ---
    try:
        if MODE == "test":
            # test モードは実際には投稿せず、内容をログ出力するだけ
            logging.info(f"[TEST]{label}\n{post_text}")
        else:
            post_bluesky(bsky_client, post_text, post_url)
            # 連続投稿によるレート制限を避けるためランダムに待機（30〜90秒）
            time.sleep(random.randint(30, 90))

        # --- 6a. 投稿成功時の state 更新 ---
        current_retry_count = site_state["entries"].get(entry_key, {}).get("retry_count", 0)

        if gemini_failed:
            # フォールバック投稿成功: retry_count を増やし、上限未満なら次回再要約のため retry_ids に登録
            new_retry_count = current_retry_count + 1
            final_status = "fallback"
            if new_retry_count <= GEMINI_RETRY_MAX:
                logging.info(f"[{site.get('display_name', site['type'])}] フォールバック投稿成功、次回再要約登録 (retry_count={new_retry_count}): {entry_key}")
                if entry_key not in set(site_state.get("retry_ids", [])):
                    site_state.setdefault("retry_ids", []).append(entry_key)
            else:
                # 再要約の上限に達したので retry_ids には登録しない（以降はスキップ）
                logging.info(f"[{site.get('display_name', site['type'])}] retry上限到達、retry_ids登録なし: {entry_key}")
        else:
            # 通常要約投稿成功（または retry で要約成功）: retry_ids から除去して完了扱い
            new_retry_count = current_retry_count
            final_status = "success"
            if entry_key in site_state.get("retry_ids", []):
                site_state["retry_ids"].remove(entry_key)

        # エントリの状態を更新
        entry = site_state["entries"].setdefault(entry_key, {})
        entry.update({
            "status": final_status,                                          # success / fallback
            "first_seen_at": entry.get("first_seen_at", isoformat(now)),     # 初回取得日時（上書きしない）
            "last_tried_at": isoformat(now),                                 # 最終試行日時
            "reason": "gemini_failed" if gemini_failed else "",              # 失敗理由（あれば）
            "retry_count": new_retry_count,                                  # 累積リトライ回数
            "posted_at": isoformat(now),                                     # 投稿完了日時
            "url": post_url,
            "score": item.get("score", 0),
        })

        # NVD / JVN で要約成功した場合のみ known_cves に登録して横断重複防止
        # （fallback 投稿では次回再投稿するため、まだ完了扱いにしない）
        if site["type"] in ("nvd_api", "jvn") and cid and not gemini_failed:
            if cid not in site_state.get("known_cves", []):
                site_state.setdefault("known_cves", []).append(cid)
            site_state["posted_ids"][cid] = isoformat(now)
            # posted_ids が膨らんだら古いものを削除
            pruned = prune_posted_ids(site_state["posted_ids"], now)
            if pruned > 0:
                logging.info(f"posted_ids prune: {pruned} 件削除 ({site_key})")

        log_label = "[フォールバック]" if gemini_failed else ""
        logging.info(f"[{site.get('display_name', site['type'])}]{label}{log_label} 投稿成功: {entry_key}")
        return "success"

    except Exception as e:
        # --- 6b. 投稿失敗時の state 更新 ---
        retry_count = site_state["entries"].get(entry_key, {}).get("retry_count", 0) + 1
        logging.warning(f"[{site.get('display_name', site['type'])}]{label} 投稿失敗 (retry_count={retry_count}): {e}")

        site_state["entries"].setdefault(entry_key, {}).update({
            "status": "failed",
            "first_seen_at": site_state["entries"].get(entry_key, {}).get("first_seen_at", isoformat(now)),
            "last_tried_at": isoformat(now),
            "reason": str(e),           # エラー内容を記録（デバッグ用）
            "retry_count": retry_count,
            "posted_at": None,          # 未投稿なので None
            "url": post_url,
            "score": item.get("score", 0),
        })

        # 次回実行で再試行するために retry_ids に追加（重複登録は防ぐ）
        existing_retries = set(site_state.get("retry_ids", []))
        if entry_key not in existing_retries:
            site_state.setdefault("retry_ids", []).append(entry_key)

        return "failed"


# =========================================================
# エントリポイント
# =========================================================

def main():
    """ボットのメイン処理。

    全サイトを順番に処理し、最後に state を保存する。
    MODE が "test" の場合は Bluesky への実際の投稿は行わず、state も保存しない。
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    # --- 設定・state の読み込み ---
    config = load_config()
    settings = config.get("settings", {})
    sites = config.get("sites", {})

    MODE = settings.get("mode", "test").lower()           # "prod" or "test"
    force_test = settings.get("force_test_mode", False)   # True の場合 Gemini を呼ばない
    skip_first = settings.get("skip_existing_on_first_run", True)  # 初回実行時に既存記事をスキップするか

    # state を深コピーして作業用に使う（失敗時にファイルへの書き込みを防ぐため）
    original_state = load_state()
    state = json.loads(json.dumps(original_state))
    state_dirty = False  # state に変更があった場合のみ保存するためのフラグ

    now = utc_now()
    gemini_key = os.environ.get("GEMINI_API_KEY")

    # =========================================================
    # Bluesky ログイン（prod モード時のみ）
    # タイムアウト延長 + 指数バックオフリトライ付き
    # =========================================================
    bsky_client = None
    if MODE == "prod":
        bsky_client = Client(base_url="https://bsky.social")

        # デフォルトのタイムアウト（約5秒）では get_profile 等でタイムアウトしやすいため 30 秒に延長
        bsky_client.request._client = httpx.Client(timeout=30.0)

        # 一時的なネットワーク遅延に対応するため最大 3 回リトライ
        # 待機時間: 5秒 → 10秒 → 3回目失敗で例外を上げて終了
        for attempt in range(1, 4):
            try:
                bsky_client.login(
                    os.environ.get("BLUESKY_IDENTIFIER"),
                    os.environ.get("BLUESKY_PASSWORD")
                )
                logging.info("Bluesky login successful")
                break
            except InvokeTimeoutError:
                logging.warning(f"Bluesky login timeout (attempt {attempt}/3)")
                if attempt == 3:
                    raise  # 3回全て失敗したら処理を中断
                time.sleep(5 * attempt)  # 5秒 → 10秒

    # =========================================================
    # サイトごとの処理ループ
    # =========================================================
    for site_key, site in sites.items():
        # enabled: false のサイトはスキップ
        if not site.get("enabled", False):
            continue

        logging.info(f"[{site_key}] ---")

        # サイト単位の集計カウンタ（最後にサマリログで出力）
        fetched_count = 0
        posted_count = 0
        retry_posted_count = 0
        cve_skip_count = 0
        fail_count = 0
        first_skip = False

        # --- state の正規化（旧フォーマット対応） ---
        site_state, migrated = normalize_site_state(site_key, state.get(site_key), now, MODE)
        state[site_key] = site_state
        if migrated:
            if MODE == "prod":
                logging.info(f"Migrate state for {site_key} (prod)")
                state_dirty = True
            else:
                logging.info(f"Migrate state for {site_key} (TEST: not saved)")

        # --- 取得対象の時間窓を決定 ---
        last_checked = site_state.get("last_checked_at")
        if last_checked:
            # 前回チェック日時以降の記事のみ取得
            since = parse_iso(last_checked)
        else:
            # 初回実行: 過去 1 日分を取得対象にする
            since = now - timedelta(days=1)
            # skip_existing_on_first_run=True の場合、初回は既存記事を投稿せずスキップ
            first_skip = skip_first and MODE == "prod"

        until = now

        # =========================================================
        # STEP 1: retry_ids の再試行（通常記事より先に処理）
        # =========================================================
        # 前回実行で失敗した記事（Gemini失敗フォールバック / 投稿エラー）を再試行する。
        # RETRY_LIMIT 件だけ処理し、残りは次回実行に持ち越す（1回の実行で処理しすぎない）。
        retry_ids_snapshot = list(site_state.get("retry_ids", []))[:RETRY_LIMIT]
        if retry_ids_snapshot:
            logging.info(f"[{site_key}] retry_ids 再試行: {len(retry_ids_snapshot)} 件")

        for entry_key in retry_ids_snapshot:
            # テキストは state に保存しないため、ソースから再取得する
            retry_item = fetch_item_for_retry(entry_key, site, site_state)
            if retry_item is None:
                # 記事が見つからない場合（フィードから消えた等）は次回に持ち越し
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

            # retry_ids の除去は process_item 内で完結しているためここではカウントのみ
            if result == "success":
                retry_posted_count += 1
            # "failed"  → retry_ids に残ったまま次回再試行
            # "skipped" → process_item 内で retry_ids から除去済み

        # =========================================================
        # STEP 2: 通常記事の取得・処理
        # =========================================================
        try:
            # サイト種別に応じたフェッチ関数を呼び出す
            if site["type"] == "rss":
                items = fetch_rss(site, since, until)
            elif site["type"] == "nvd_api":
                items = fetch_nvd(site, since, until)
            elif site["type"] in ("jvn", "jvn_rss"):
                items = fetch_jvn(site, since, until)
            else:
                continue  # 未対応種別はスキップ
        except RuntimeError as fetch_err:
            # NVD 429 等、フェッチレベルの失敗。
            # last_checked_at を進めないことで次回同じ時間窓を再取得する。
            # STEP 1 の retry 処理結果は保存するため state_dirty = True にする。
            logging.warning(f"[{site_key}] 記事取得失敗のため通常処理をスキップ: {fetch_err}")
            logging.info(f"[{site_key}] fetched=0, posted=0, retry_posted={retry_posted_count}, skipped=0, failed=0, retry_pending={len(site_state.get('retry_ids', []))}")
            state_dirty = True
            continue

        fetched_count = len(items)

        if first_skip:
            # 初回実行: 既存記事は投稿せず、ステータスも記録しない
            logging.info(f"[{site_key}] 初回実行のため既存記事 {fetched_count} 件をスキップ")
        else:
            for item in items:
                cid = item.get("id")
                entry_key = cid or item.get("url")

                # 既に success / fallback ステータスの記事は再処理しない
                # （fallback は retry_ids 経由で別途再試行される）
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

        # チェック完了時刻を更新（次回実行時の取得開始時刻になる）
        site_state["last_checked_at"] = isoformat(now)
        state_dirty = True

        # サイト単位の処理サマリをログ出力
        logging.info(
            f"[{site_key}] fetched={fetched_count}, posted={posted_count}, "
            f"retry_posted={retry_posted_count}, skipped={cve_skip_count}, "
            f"failed={fail_count}, retry_pending={len(site_state.get('retry_ids', []))}"
        )

    # --- 全サイト処理完了後、state を保存 ---
    # prod モードかつ変更がある場合のみ書き込む（test モードでは変更しない）
    if MODE == "prod" and state_dirty:
        save_state(state)


if __name__ == "__main__":
    main()
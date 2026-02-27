# =========================
# State v2 helpers
# =========================

def load_state(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_site_state(state: dict, site_key: str) -> dict:
    """
    State v2:
    site_key 単位で dict を持つ
    """
    return state.setdefault(site_key, {})


def save_state(path: str, state: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


# =========================
# Main site processing
# =========================

def process_site(site_key: str, site: dict, state: dict, MODE: str):
    logger.info(f"[site] --- {site_key} ---")

    site_state = get_site_state(state, site_key)

    last_checked_at = site_state.get("last_checked_at")
    is_first_run = last_checked_at is None

    skip_existing = (
        MODE == "prod"
        and site.get("skip_existing_on_first_run", False)
        and is_first_run
    )

    if skip_existing:
        logger.info(
            f"[{site_key}] first run detected → skip existing items (safety guard)"
        )

    entries = fetch_entries(site, last_checked_at)

    posted_count = 0
    skipped_count = 0
    api_error_occurred = False

    for entry in entries:
        entry_time = entry["published_at"]

        # --- 初回スキップ ---
        if skip_existing:
            skipped_count += 1
            continue

        # --- 時間軸チェック ---
        if last_checked_at and entry_time <= last_checked_at:
            skipped_count += 1
            continue

        body = body_trim(entry)

        # =========================
        # Summary handling
        # =========================

        force_test = site.get("force_test_mode", False)

        if MODE == "test" and force_test:
            summary = "[TEST SUMMARY]"
            summary_status = "success"
        else:
            summary, summary_status = summarize_with_retry(body)

        # --- API エラー即停止 ---
        if summary_status in ("api_error", "rate_limited"):
            logger.warning(
                f"[{site_key}] Gemini API error ({summary_status}) → abort site"
            )
            api_error_occurred = True
            break

        # =========================
        # Post
        # =========================

        post_text = build_post_text(entry, summary)

        if MODE == "test":
            logger.info(f"[TEST] 投稿内容:\n{post_text}")
        else:
            post(post_text)

        posted_count += 1

        # =========================
        # State update (entry-level)
        # =========================

        # CVE 系のみ posted_ids を管理
        if site["type"] in ("nvd", "jvn"):
            posted_ids = site_state.setdefault("posted_ids", [])
            cve_id = entry.get("cve_id")

            if cve_id and cve_id not in posted_ids:
                posted_ids.append(cve_id)
                logger.info(f"[{site_key}] posted_id added: {cve_id}")

    # =========================
    # State finalize
    # =========================

    if not api_error_occurred and MODE == "prod":
        # 正常終了時のみ last_checked_at 更新
        site_state["last_checked_at"] = now_utc_iso()

    logger.info(
        f"[{site_key}] summary: posted={posted_count}, skipped={skipped_count}, "
        f"last_checked_at={'unchanged' if api_error_occurred else site_state.get('last_checked_at')}"
    )
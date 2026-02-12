import os
import requests
from datetime import datetime, timedelta
import time

# ========= 設定 =========
DRY_RUN = True  # 本番時は False
CVSS_THRESHOLD = 7.0
MAX_POST_ITEMS = 3


# ========= NVD API取得 =========
def fetch_nvd_recent():

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z"
    now = datetime.utcnow().isoformat() + "Z"

    params = {
        "pubStartDate": yesterday,
        "pubEndDate": now,
        "resultsPerPage": 50
    }

    response = requests.get(base_url, params=params, timeout=30)
    response.raise_for_status()

    data = response.json()
    results = []

    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]

        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            ""
        )

        metrics = cve.get("metrics", {})
        score = None

        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        results.append({
            "id": cve_id,
            "description": description,
            "score": score
        })

    return results


# ========= CVSSフィルタ =========
def filter_high_severity(vulns, threshold):
    return [
        v for v in vulns
        if v["score"] is not None and v["score"] >= threshold
    ]


# ========= スコア順ソート =========
def sort_by_score_desc(vulns):
    return sorted(vulns, key=lambda x: x["score"], reverse=True)


# ========= CVE API補完（任意） =========
def fetch_cve_detail(cve_id):

    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    try:
        response = requests.get(url, timeout=15)

        if response.status_code != 200:
            return None

        data = response.json()

        return data["containers"]["cna"]["descriptions"][0]["value"]

    except Exception:
        return None


# ========= 投稿文生成 =========
def build_daily_post(vulns):

    if not vulns:
        return "【本日の重大CVE】\nCVSS7.0以上の新規公開CVEは確認されませんでした。\n\nhttps://nvd.nist.gov/"

    lines = ["【本日の重大CVE（CVSS 7.0以上）】"]

    for v in vulns[:MAX_POST_ITEMS]:

        line = f"{v['id']}"

        if v["score"]:
            line += f" (CVSS {v['score']})"

        desc = v["description"].replace("\n", " ")
        desc = desc[:80] + "..." if len(desc) > 80 else desc

        line += f"\n{desc}"

        lines.append(line)

    lines.append("\n詳細:")
    lines.append("https://nvd.nist.gov/")

    return "\n\n".join(lines)


# ========= Bluesky投稿（ダミー） =========
def post_to_bluesky(text):
    print("=== Bluesky投稿 ===")
    print(text)
    # 本番時ここにAPI実装


# ========= メイン =========
def main():

    print("=== NVD Daily Secure Mode ===")

    try:
        vulns = fetch_nvd_recent()

        high = filter_high_severity(vulns, CVSS_THRESHOLD)

        sorted_vulns = sort_by_score_desc(high)

        post_text = build_daily_post(sorted_vulns)

        if DRY_RUN:
            print("[DRY RUN]")
            print(post_text)
        else:
            post_to_bluesky(post_text)

    except Exception as e:
        print("エラー:", e)

    print("=== end ===")


if __name__ == "__main__":
    main()

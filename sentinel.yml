#!/usr/bin/env python3
"""
Tiger Sentinel v6 — full dev.to scan.
Scans ALL articles on dev.to (paginated until API returns empty).
Reads comments only. Logs what it found and what it scanned, page by page.
Runs in GitHub Actions. Designed for a 6-hour job timeout.
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# ── CONFIG ──────────────────────────────────────────────────────────────────
STATE_FILE = "sentinel_state.json"
OUT_REPORT = "findings_report.json"
OUT_REVIEW = "findings_review.json"
DELAY_BETWEEN_ARTICLES = 3.5
DELAY_BETWEEN_PAGES = 2.0
MAX_RUNTIME_SECONDS = 5 * 60 * 60
USER_AGENT = "TigerSentinel/6.0 (dev.to community moderation; full-scan)"

START = time.time()

PHISHING_DOMAINS = {"labagent.tech", "labagent.io", "suppdev.io", "suppdev.tech"}
SHORTLINK_DOMAINS = {
    "bit.ly", "tr.ee", "t.co", "tinyurl.com", "shorturl.at",
    "cutt.ly", "clck.su", "rb.gy", "goo.gl", "ow.ly", "is.gd",
}
IMPERSONATION_PHRASES = [
    "official platform update", "verify your account", "security protocols",
    "you have 24 hours", "you have 14 hours", "finish this confirmation",
    "click here to secure", "claim your reward", "account suspended",
    "confirm your identity", "urgent action required", "final warning",
]
BOILERPLATE = ["enter fullscreen mode", "exit fullscreen mode", "link at the end"]

VN_REGEX = re.compile(
    r"[ăâđêôơưàảãáạằẳẵắặầẩẫấậèẻẽéẹềểễếệìỉĩíịòỏõóọồổỗốộờởỡớợùủũúụừửữứựỳỷỹýỵ]",
    re.IGNORECASE,
)
BOT_USERNAME = re.compile(r"^[a-z]+_[a-z]+_[0-9a-f]{8,}$|^[a-z]{4,}[0-9]{5,}$|^[a-z]+_[0-9]{8,}$")

REPORT = []
REVIEW = []
DOMAIN_ACCOUNTS = {}
SCANNED_PAGES = 0
SCANNED_ARTICLES = 0


def log(msg):
    elapsed = int(time.time() - START)
    print(f"[{elapsed}s] {msg}", flush=True)


def time_up():
    return (time.time() - START) > MAX_RUNTIME_SECONDS


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"last_article_id": None, "scanned_count": 0}


def save_state(state):
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def fetch_json(url):
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(req, timeout=30) as r:
            return json.load(r)
    except HTTPError as e:
        if e.code == 429:
            log("429 rate limited — sleeping 60s")
            time.sleep(60)
            return None
        log(f"HTTP {e.code} on {url}")
        return None
    except Exception as e:
        log(f"Fetch error: {e}")
        return None


def strip_html(s):
    return re.sub(r"<[^>]+>", "", s or "").strip()


def score_comment(text, username):
    lower = text.lower()
    strong, weak = [], []

    for d in PHISHING_DOMAINS:
        if d in lower:
            strong.append(f"phishing-domain:{d}")

    imp_hits = [p for p in IMPERSONATION_PHRASES if p in lower]
    if len(imp_hits) >= 2:
        strong.append(f"impersonation-pair:{'|'.join(imp_hits)}")
    elif len(imp_hits) == 1:
        weak.append(f"imp-phrase:{imp_hits[0]}")

    short_hit = next((d for d in SHORTLINK_DOMAINS if d in lower), None)
    if short_hit:
        if VN_REGEX.search(text):
            strong.append(f"shortlink+vn:{short_hit}")
        elif len(text) < 20:
            strong.append(f"shortlink+near-empty:{short_hit}")
        elif BOT_USERNAME.match(username):
            strong.append(f"shortlink+bot-username:{short_hit}")
        else:
            weak.append(f"shortlink:{short_hit}")
        DOMAIN_ACCOUNTS.setdefault(short_hit, set()).add(username)

    if VN_REGEX.search(text) and not any(s.startswith("shortlink") for s in strong):
        weak.append("vietnamese-text")
    for p in BOILERPLATE:
        if p in lower:
            weak.append(f"boilerplate:{p}")

    if len(strong) >= 2:
        return "report", strong + weak
    if strong or weak:
        return "review", strong + weak
    return None, []


def scan_article(article, seen_comments):
    url = f"https://dev.to/api/comments?a_id={article['id']}"
    comments = fetch_json(url)
    if not comments:
        return
    for c in comments:
        if time_up():
            return
        cid = c.get("id_code")
        if not cid or cid in seen_comments:
            continue
        seen_comments.add(cid)
        text = strip_html(c.get("body_html", ""))
        username = (c.get("user") or {}).get("username", "unknown")
        tier, reasons = score_comment(text, username)
        if not tier:
            continue
        record = {
            "username": username,
            "comment_url": f"https://dev.to{article['path']}#comment-{cid}",
            "article_title": article["title"],
            "reasons": reasons,
            "content": text[:500],
        }
        if tier == "report":
            REPORT.append(record)
            log(f"  !!! REPORT: @{username} — {', '.join(reasons)}")
            log(f"      Content: {text[:200]}")
        else:
            REVIEW.append(record)


def write_outputs():
    clusters = []
    for domain, accounts in DOMAIN_ACCOUNTS.items():
        if len(accounts) >= 3:
            clusters.append({
                "domain": domain,
                "account_count": len(accounts),
                "accounts": sorted(accounts),
            })
    clusters.sort(key=lambda c: -c["account_count"])

    with open(OUT_REPORT, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "pages_scanned": SCANNED_PAGES,
            "articles_scanned": SCANNED_ARTICLES,
            "reportable_count": len(REPORT),
            "unique_accounts": len(set(r["username"] for r in REPORT)),
            "clusters": clusters,
            "findings": REPORT,
        }, f, indent=2)

    with open(OUT_REVIEW, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "review_count": len(REVIEW),
            "findings": REVIEW,
        }, f, indent=2)

    log(f"\n=== DONE ===")
    log(f"Pages scanned: {SCANNED_PAGES}")
    log(f"Articles scanned: {SCANNED_ARTICLES}")
    log(f"Reportable findings: {len(REPORT)}")
    log(f"Review findings: {len(REVIEW)}")
    log(f"Clusters (3+ accounts): {len(clusters)}")
    for c in clusters[:5]:
        log(f"  {c['domain']}: {c['account_count']} accounts")


def main():
    global SCANNED_PAGES, SCANNED_ARTICLES
    log("Tiger Sentinel v6 — full dev.to scan")
    state = load_state()
    seen_articles = set()
    seen_comments = set()
    log(f"Resume state: {state.get('scanned_count', 0)} articles scanned previously")

    page = 1
    while not time_up():
        log(f"Scanning page {page}...")
        batch = fetch_json(f"https://dev.to/api/articles?page={page}&per_page=100")
        if batch is None:
            log(f"Page {page} fetch failed — stopping")
            break
        if len(batch) == 0:
            log(f"Page {page} empty — end of dev.to. Scan complete.")
            break
        SCANNED_PAGES = page
        log(f"  Got {len(batch)} articles on page {page}")
        for i, article in enumerate(batch):
            if time_up():
                log("Time limit reached — stopping gracefully")
                save_state(state)
                write_outputs()
                return
            aid = article["id"]
            if aid in seen_articles:
                continue
            seen_articles.add(aid)
            log(f"  [{i+1}/{len(batch)}] {article['title'][:60]} — @{article.get('user', {}).get('username', '?')}")
            scan_article(article, seen_comments)
            SCANNED_ARTICLES += 1
            state["last_article_id"] = aid
            state["scanned_count"] = state.get("scanned_count", 0) + 1
            if SCANNED_ARTICLES % 10 == 0:
                save_state(state)
            time.sleep(DELAY_BETWEEN_ARTICLES)
        page += 1
        time.sleep(DELAY_BETWEEN_PAGES)

    save_state(state)
    write_outputs()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"FATAL: {e}")
        sys.exit(1)

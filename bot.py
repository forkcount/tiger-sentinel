#!/usr/bin/env python3
"""
Tiger Sentinel v7.1 — web-wide search for labagent.tech.
Fixed Common Crawl endpoint. Logs the FULL URL for every finding, never truncated.
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import quote

TARGET_DOMAIN = "labagent.tech"
STATE_FILE = "sentinel_state.json"
OUT_REPORT = "findings_report.json"
OUT_REVIEW = "findings_review.json"

DELAY_DEVTO = 3.5
DELAY_COMMONCRAWL = 2.0
DELAY_URLSCAN = 10.0
MAX_RUNTIME_SECONDS = 5 * 60 * 60
USER_AGENT = "TigerSentinel/7.1 (dev.to community moderation; web-wide scan)"

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
SEEN_URLS = set()


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


def fetch_json(url, headers=None):
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = Request(url, headers=h)
    try:
        with urlopen(req, timeout=30) as r:
            return json.load(r)
    except HTTPError as e:
        if e.code == 429:
            log(f"429 on {url} — sleeping 60s")
            time.sleep(60)
            return None
        log(f"HTTP {e.code} on {url}")
        return None
    except Exception as e:
        log(f"Fetch error {url}: {e}")
        return None


def strip_html(s):
    return re.sub(r"<[^>]+>", "", s or "").strip()


def log_finding(source, url, title, snippet, timestamp=None):
    if url in SEEN_URLS:
        return
    SEEN_URLS.add(url)
    print("", flush=True)
    print(f"  [FOUND] Source: {source}", flush=True)
    print(f"  [FOUND] URL: {url}", flush=True)
    if title:
        print(f"  [FOUND] Title: {title}", flush=True)
    if timestamp:
        print(f"  [FOUND] Timestamp: {timestamp}", flush=True)
    if snippet:
        print(f"  [FOUND] Snippet: {snippet}", flush=True)
    print("", flush=True)
    REPORT.append({
        "source": source, "url": url,
        "title": title or "", "snippet": snippet or "",
        "timestamp": timestamp or "",
    })


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
        comment_url = f"https://dev.to{article['path']}#comment-{cid}"
        if tier == "report":
            log_finding("dev.to", comment_url, article["title"],
                        f"@{username} — {', '.join(reasons)}\n{text[:200]}")
        else:
            REVIEW.append({
                "source": "dev.to", "url": comment_url,
                "title": article["title"], "snippet": text[:500],
                "username": username, "reasons": reasons,
            })


def scan_devto():
    global SCANNED_PAGES, SCANNED_ARTICLES
    log("=== dev.to scan ===")
    state = load_state()
    seen_articles = set()
    seen_comments = set()
    page = 1
    while not time_up():
        log(f"Scanning page {page}...")
        batch = fetch_json(f"https://dev.to/api/articles?page={page}&per_page=100")
        if batch is None:
            break
        if len(batch) == 0:
            log(f"Page {page} empty — end of dev.to")
            break
        SCANNED_PAGES = page
        for article in batch:
            if time_up():
                break
            aid = article["id"]
            if aid in seen_articles:
                continue
            seen_articles.add(aid)
            scan_article(article, seen_comments)
            SCANNED_ARTICLES += 1
            state["last_article_id"] = aid
            state["scanned_count"] = state.get("scanned_count", 0) + 1
            if SCANNED_ARTICLES % 10 == 0:
                save_state(state)
            time.sleep(DELAY_DEVTO)
        page += 1
    save_state(state)
    log(f"dev.to scan done — {SCANNED_ARTICLES} articles, {SCANNED_PAGES} pages")


def scan_commoncrawl():
    log("=== Common Crawl scan ===")
    # Get the latest index name from collinfo
    coll = fetch_json("https://index.commoncrawl.org/collinfo.json")
    if not coll or len(coll) == 0:
        log("Common Crawl: could not fetch index list")
        return

    # Try the most recent 3 indexes in case the newest one is unavailable
    tried = 0
    for entry in coll[:3]:
        index_name = entry.get("id", "")
        if not index_name:
            continue
        tried += 1
        log(f"Trying Common Crawl index: {index_name}")

        query = quote(f"{TARGET_DOMAIN}/*", safe="")
        url = f"https://index.commoncrawl.org/{index_name}-index?url={query}&output=json"

        req = Request(url, headers={"User-Agent": USER_AGENT})
        count = 0
        try:
            with urlopen(req, timeout=60) as r:
                for line in r:
                    if time_up():
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("status") != "200":
                        continue
                    full_url = record.get("url", "")
                    if not full_url:
                        continue
                    log_finding("commoncrawl", full_url, "",
                                f"status={record.get('status')} mime={record.get('mime', '')}",
                                record.get("timestamp", ""))
                    count += 1
                    if count >= 1000:
                        log("Common Crawl: 1000 URL cap reached")
                        break
                    time.sleep(0.1)
            log(f"Common Crawl ({index_name}) done — {count} URLs found")
            if count > 0:
                break  # Found results, no need to try older indexes
        except HTTPError as e:
            log(f"Common Crawl ({index_name}) HTTP {e.code} — trying next index")
            continue
        except Exception as e:
            log(f"Common Crawl ({index_name}) error: {e} — trying next index")
            continue

    if tried == 0:
        log("Common Crawl: no usable indexes found")
    time.sleep(DELAY_COMMONCRAWL)


def scan_urlscan():
    log("=== urlscan.io scan ===")
    query = quote(f"domain:{TARGET_DOMAIN}", safe=":")
    url = f"https://urlscan.io/api/v1/search/?q={query}&size=100"
    data = fetch_json(url, headers={"User-Agent": USER_AGENT})
    if not data:
        log("urlscan.io: no data returned")
        return
    results = data.get("results", [])
    log(f"urlscan.io: {len(results)} results")
    for r in results:
        if time_up():
            break
        page = r.get("page", {})
        task = r.get("task", {})
        full_url = page.get("url", "")
        if not full_url:
            continue
        log_finding("urlscan", full_url, page.get("title", ""),
                    f"scan_id={task.get('uuid', '')}", task.get("time", ""))
        time.sleep(0.2)
    time.sleep(DELAY_URLSCAN)


def write_outputs():
    clusters = []
    for domain, accounts in DOMAIN_ACCOUNTS.items():
        if len(accounts) >= 3:
            clusters.append({"domain": domain, "account_count": len(accounts),
                             "accounts": sorted(accounts)})
    clusters.sort(key=lambda c: -c["account_count"])
    with open(OUT_REPORT, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_domain": TARGET_DOMAIN,
            "pages_scanned": SCANNED_PAGES,
            "articles_scanned": SCANNED_ARTICLES,
            "reportable_count": len(REPORT),
            "clusters": clusters,
            "findings": REPORT,
        }, f, indent=2)
    with open(OUT_REVIEW, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "review_count": len(REVIEW),
            "findings": REVIEW,
        }, f, indent=2)
    log("")
    log("=== DONE ===")
    log(f"Pages scanned: {SCANNED_PAGES}")
    log(f"Articles scanned: {SCANNED_ARTICLES}")
    log(f"Reportable findings: {len(REPORT)}")
    log(f"Review findings: {len(REVIEW)}")
    log(f"Outputs: {OUT_REPORT}, {OUT_REVIEW}")


def main():
    log("Tiger Sentinel v7.1 — web-wide search for labagent.tech")
    scan_devto()
    scan_commoncrawl()
    scan_urlscan()
    write_outputs()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"FATAL: {e}")
        sys.exit(1)

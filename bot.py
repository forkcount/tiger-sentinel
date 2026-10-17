import json
import os
import re
import time
import requests

PAGES_TO_SCAN = 5
PER_PAGE = 100
DELAY_BETWEEN_REQUESTS = 3
PAUSE_EVERY_N_ARTICLES = 10
PAUSE_DURATION = 60
SLEEP_WHEN_CAUGHT_UP = 600
STATE_FILE = 'sentinel-state.json'
FINDINGS_FILE = 'tiger-sentinel-findings.json'

SUSPICIOUS_DOMAINS = [
    'labgent.tech', 'labagent.tech', 'bit.ly', 'tr.ee', 't.co',
    'tinyurl.com', 'shorturl.at', 'cutt.ly', 'offerup-pay.top', 'clck.su'
]
SUSPICIOUS_PHRASES = [
    'security update', 'verify your account', 'claim your reward',
    'click here to secure', 'finish this confirmation', 'dev support',
    'enter fullscreen mode', 'you have 14 hours', 'official platform update',
    'security protocols'
]
VIETNAMESE_REGEX = re.compile(
    r'[ăâđêôơưàảãáạằẳẵắặầẩẫấậèẻẽéẹềểễếệìỉĩíịòỏõóọồổỗốộờởỡớợùủũúụừửữứựỳỷỹýỵ]',
    re.IGNORECASE
)
NEW_ACCOUNT_DAYS = 7

headers = {"Content-Type": "application/json", "User-Agent": "TigerSentinel/3.0"}
findings = []
account_profiles = {}


def load_state():
    if not os.path.exists(STATE_FILE):
        return {"scanned_article_ids": []}
    try:
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {"scanned_article_ids": []}


def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


def save_findings():
    if not findings:
        print("No findings to save.")
        return
    all_findings = []
    if os.path.exists(FINDINGS_FILE):
        try:
            with open(FINDINGS_FILE, 'r') as f:
                all_findings = json.load(f)
        except Exception:
            all_findings = []
    all_findings.extend(findings)
    with open(FINDINGS_FILE, 'w') as f:
        json.dump(all_findings, f, indent=2)
    print(f"Saved {len(findings)} new findings. Total: {len(all_findings)}")


def days_since(date_str):
    if not date_str:
        return 9999
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return 9999


def extract_links(text):
    return re.findall(r'(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}[^\s]*', text, re.IGNORECASE)


def analyze_comment(comment, article, username):
    raw_html = comment.get('body_html', '') or ''
    text = re.sub(r'<[^>]+>', '', raw_html)
    reasons = []
    if VIETNAMESE_REGEX.search(text):
        reasons.append('vietnamese-text')
    links = extract_links(text)
    for link in links:
        for d in SUSPICIOUS_DOMAINS:
            if d in link.lower():
                reasons.append(f'domain:{d}')
    for p in SUSPICIOUS_PHRASES:
        if p in text.lower():
            reasons.append(f'phrase:{p}')
    account_age = days_since(comment.get('user', {}).get('joined_at'))
    if account_age < NEW_ACCOUNT_DAYS:
        reasons.append(f'new-account:{account_age}d')
    trimmed = text.strip()
    if links and trimmed.endswith(links[-1]):
        reasons.append('link-at-end')
    for link in links:
        if re.search(r'tr\.ee|bit\.ly|tinyurl|t\.co|cutt\.ly|clck\.su', link, re.IGNORECASE):
            reasons.append('shortlink')
    if re.search(r'within|deadline|hours|minutes|expire|urgent', text, re.IGNORECASE):
        reasons.append('urgency-phrase')
    if re.search(r'dev\s*(support|team|to\s*support)|sincerely.*dev', text, re.IGNORECASE):
        reasons.append('impersonation')
    if re.search(r'verify.*account|confirm.*account|confirm.*identity|link is in the profile', text, re.IGNORECASE):
        reasons.append('fake-verification')
    if re.search(r'enter fullscreen mode|exit fullscreen mode', text, re.IGNORECASE):
        reasons.append('html-artifact')
    if len(text) > 500 and links:
        reasons.append('long-with-link')
    if VIETNAMESE_REGEX.search(text) and re.search(r'you need|verify|click here', text, re.IGNORECASE):
        reasons.append('mixed-language')
    if len(text.strip()) < 15:
        reasons.append('near-empty')
    if username not in account_profiles:
        account_profiles[username] = {'comments': [], 'suspicious_count': 0}
    account_profiles[username]['comments'].append({
        'text': text[:200], 'article_id': article['id'],
        'article_title': article['title'], 'comment_id': comment.get('id_code'),
        'created_at': comment.get('created_at'), 'reasons': reasons
    })
    return reasons


def score_account(username):
    profile = account_profiles.get(username)
    if not profile or not profile['comments']:
        return {'score': 0, 'tags': []}
    all_reasons = []
    for c in profile['comments']:
        all_reasons.extend(c['reasons'])
    unique_reasons = list({r.split(':')[0] for r in all_reasons})
    tags = []
    if sum(1 for c in profile['comments'] if len(c['reasons']) >= 2) >= 2:
        tags.append('serial-offender')
    domain_counts = {}
    for c in profile['comments']:
        for r in c['reasons']:
            if r.startswith('domain:'):
                domain_counts[r] = domain_counts.get(r, 0) + 1
    for dom, count in domain_counts.items():
        if count >= 2:
            tags.append(f"repeated-domain:{dom.replace('domain:', '')}")
    times = []
    for c in profile['comments']:
        if c['created_at']:
            try:
                from datetime import datetime
                times.append(datetime.fromisoformat(c['created_at'].replace('Z', '+00:00')).timestamp())
            except Exception:
                pass
    times.sort()
    for i in range(1, len(times)):
        if times[i] - times[i - 1] < 3600:
            tags.append('burst-posting')
            break
    if len(profile['comments']) >= 3:
        first = ','.join(profile['comments'][0]['reasons'])
        if all(','.join(c['reasons']) == first for c in profile['comments']) and profile['comments'][0]['reasons']:
            tags.append('identical-signature')
    if 'vietnamese-text' in unique_reasons and len(unique_reasons) >= 2:
        tags.append('vn-plus-signal')
    if len(profile['comments']) >= 2:
        tags.append('multiple-articles')
    return {
        'score': sum(1 for c in profile['comments'] if len(c['reasons']) >= 2),
        'tags': list(set(tags))
    }


def fetch_json(url):
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code == 429:
        print("  RATE LIMITED. Waiting 90s...")
        time.sleep(90)
        raise Exception('rate limited')
    if r.status_code != 200:
        raise Exception(f'{r.status_code} on {url}')
    return r.json()


def fetch_all_articles():
    all_articles = []
    for page in range(1, PAGES_TO_SCAN + 1):
        print(f"  Fetching article list, page {page}/{PAGES_TO_SCAN}...")
        try:
            batch = fetch_json(f"https://dev.to/api/articles?per_page={PER_PAGE}&page={page}")
        except Exception as e:
            print(f"  Page {page} failed: {e}")
            break
        if not batch:
            print(f"  Page {page} is empty. End of feed.")
            break
        all_articles.extend(batch)
        time.sleep(2)
    return all_articles


def scan_article(article):
    print(f"Scanning: {article['title'][:50]}...")
    try:
        comments = fetch_json(f"https://dev.to/api/comments?a_id={article['id']}")
    except Exception as e:
        print(f"  skipped ({e})")
        return
    print(f"  {len(comments)} comments")
    for c in comments:
        username = c.get('user', {}).get('username', 'unknown')
        reasons = analyze_comment(c, article, username)
        if len(reasons) >= 2:
            findings.append({
                'username': username,
                'joined': c.get('user', {}).get('joined_at', 'unknown'),
                'account_age_days': days_since(c.get('user', {}).get('joined_at')),
                'article_title': article['title'],
                'article_url': f"https://dev.to{article['path']}",
                'comment_url': f"https://dev.to{article['path']}#comment-{c.get('id_code')}",
                'reasons': reasons,
                'snippet': re.sub(r'<[^>]+>', '', c.get('body_html', ''))[:300]
            })
            print(f"  !!! FOUND: @{username} — {', '.join(reasons)}")


def main():
    print("Tiger Sentinel v3 — paginated scan")
    print(f"Scanning pages 1-{PAGES_TO_SCAN} of dev.to (up to {PAGES_TO_SCAN * PER_PAGE} articles)\n")
    state = load_state()
    seen = set(state.get('scanned_article_ids', []))
    print(f"Loaded state: {len(seen)} articles already scanned.\n")
    while True:
        print("Fetching article list...")
        try:
            all_articles = fetch_all_articles()
        except Exception as e:
            print(f"  Failed to fetch: {e}. Sleeping 10 min...")
            time.sleep(SLEEP_WHEN_CAUGHT_UP)
            continue
        print(f"Got {len(all_articles)} articles from {PAGES_TO_SCAN} pages.\n")
        unseen = [a for a in all_articles if a['id'] not in seen]
        print(f"{len(unseen)} of those are unseen. Scanning...\n")
        if not unseen:
            print(f"All articles already scanned. Sleeping {SLEEP_WHEN_CAUGHT_UP // 60} min...\n")
            time.sleep(SLEEP_WHEN_CAUGHT_UP)
            continue
        since_last_pause = 0
        for a in unseen:
            scan_article(a)
            seen.add(a['id'])
            state['scanned_article_ids'].append(a['id'])
            save_state(state)
            since_last_pause += 1
            if since_last_pause >= PAUSE_EVERY_N_ARTICLES:
                print(f"\n--- Pausing {PAUSE_DURATION}s (total: {len(state['scanned_article_ids'])}) ---\n")
                time.sleep(PAUSE_DURATION)
                since_last_pause = 0
            else:
                time.sleep(DELAY_BETWEEN_REQUESTS)
        print(f"\n=== FINDINGS THIS CYCLE: {len(findings)} ===\n")
        for f in findings:
            print(f"@{f['username']}")
            print(f"  joined: {f['joined']} ({f['account_age_days']}d ago)")
            print(f"  reasons: {', '.join(f['reasons'])}")
            print(f"  comment: {f['comment_url']}")
            print()
        print("=== ACCOUNT ANALYSIS ===\n")
        linked_domains = {}
        for username, profile in account_profiles.items():
            s = score_account(username)
            if s['score'] >= 1:
                print(f"@{username} — {s['score']} suspicious — {', '.join(s['tags']) if s['tags'] else 'none'}")
                for c in profile['comments']:
                    for r in c['reasons']:
                        if r.startswith('domain:'):
                            dom = r.replace('domain:', '')
                            linked_domains.setdefault(dom, set()).add(username)
        print("\n=== CROSS-ACCOUNT ANALYSIS ===\n")
        for dom, accounts in linked_domains.items():
            if len(accounts) >= 2:
                print(f"Domain {dom} — {len(accounts)} accounts: {', '.join('@' + a for a in accounts)}")
                print("  → Possible coordinated campaign\n")
        save_findings()
        print(f"\nCycle complete. Total scanned: {len(state['scanned_article_ids'])}")
        print(f"Sleeping {SLEEP_WHEN_CAUGHT_UP // 60} min for new articles...\n")
        time.sleep(SLEEP_WHEN_CAUGHT_UP)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCaught Ctrl+C. Saving...\n")
        save_findings()
        state = load_state()
        print(f"Total articles scanned: {len(state.get('scanned_article_ids', []))}")
        print("\n=== FINAL ACCOUNT ANALYSIS ===\n")
        for username, profile in account_profiles.items():
            s = score_account(username)
            if s['score'] >= 1:
                print(f"@{username} — {s['score']} suspicious — {', '.join(s['tags']) if s['tags'] else 'no tags'}")

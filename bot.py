import requests
import os
import time

# 🐯 TIGER SENTINEL CONFIGURATION
DEV_TO_API_KEY = os.getenv("DEV_TO_API_KEY")
BASE_URL = "https://dev.to/api"

# Scam keywords to look for in comments
SCAM_KEYWORDS = ["tr.ee/dev-to", "verify your account", "official platform update", "security protocols have been updated"]

WARNING_MESSAGE = "THIS IS A PHISHING SCAM 🚨 Do not click this link. Dev.to will never ask you to verify your account via a third-party link in the comments."

def get_latest_articles():
    """Fetch the latest 30 articles from Dev.to Latest section (not featured)"""
    # Adding page=1 ensures we get chronological latest, not featured
    url = f"{BASE_URL}/articles?per_page=30&page=1"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    print(f"❌ Failed to fetch articles. Status: {response.status_code}")
    return []

def check_comments_recursive(comments, article_id):
    """Recursively check all comments (including nested replies) for scams"""
    for comment in comments:
        # Check the comment body (try multiple fields)
        body = comment.get("body_markdown", "") or comment.get("body_html", "") or ""
        body_lower = body.lower()
        
        # Debug: print what we're checking
        username = comment.get("user", {}).get("username", "unknown")
        print(f"   🔎 Checking comment by @{username}...")
        
        if any(keyword.lower() in body_lower for keyword in SCAM_KEYWORDS):
            print(f"   🚨 SCAM FOUND in comment by @{username}!")
            return True
        
        # Recursively check child comments (nested replies)
        children = comment.get("children", [])
        if children:
            if check_comments_recursive(children, article_id):
                return True
    
    return False

def get_comments_for_article(article_id):
    """Fetch all comments for a specific article"""
    url = f"{BASE_URL}/comments?a_id={article_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    print(f"   ❌ Failed to fetch comments for article {article_id}. Status: {response.status_code}")
    return []

def post_warning_comment(article_id):
    """Post the scam warning comment to the article"""
    if not DEV_TO_API_KEY:
        print("❌ CRITICAL ERROR: DEV_TO_API_KEY is missing from GitHub Secrets!")
        return False

    url = f"{BASE_URL}/comments"
    
    headers = {
        "api-key": DEV_TO_API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "comment": {
            "body_markdown": WARNING_MESSAGE,
            "commentable_id": article_id,
            "commentable_type": "Article"
        }
    }
    
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 201:
        print(f"✅ Successfully posted warning on article {article_id}!")
        return True
    else:
        print(f"❌ Failed to post on article {article_id}. Status: {response.status_code}")
        print(f"Dev.to Response: {response.text}")
        return False

def main():
    print("🐯 Tiger Sentinel: Scanning Dev.to LATEST 30 articles (chronological feed)...")
    
    articles = get_latest_articles()
    if not articles:
        print("❌ No articles found. Exiting.")
        return

    print(f"📊 Found {len(articles)} articles to scan.\n")
    
    scams_detected = 0
    
    for article in articles:
        article_id = article.get("id")
        article_title = article.get("title", "Unknown Title")
        published_at = article.get("published_at", "Unknown date")
        print(f"🔍 Checking article: '{article_title}' (ID: {article_id}, Published: {published_at})")
        
        comments = get_comments_for_article(article_id)
        
        if not comments:
            print(f"   ℹ️  No comments on this article.\n")
            continue
        
        print(f"   📝 Found {len(comments)} top-level comments. Checking recursively...")
        
        scam_found = check_comments_recursive(comments, article_id)
        
        if scam_found:
            print(f"🚨 SCAM DETECTED on article {article_id}! Deploying counter-measure...")
            post_warning_comment(article_id)
            scams_detected += 1
            time.sleep(2)
        
        print()
    
    print(f"🐯 Tiger Sentinel: Scan complete. Scams detected: {scams_detected}. Perimeter secured.")

if __name__ == "__main__":
    main()

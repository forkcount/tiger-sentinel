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
    """Fetch the latest articles from Dev.to"""
    url = f"{BASE_URL}/articles?per_page=5"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    print(f"❌ Failed to fetch articles. Status: {response.status_code}")
    return []

def get_comments_for_article(article_id):
    """Fetch comments for a specific article"""
    url = f"{BASE_URL}/comments?a_id={article_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    print(f"❌ Failed to fetch comments for article {article_id}. Status: {response.status_code}")
    return []

def post_warning_comment(article_id):
    """Post the scam warning comment to the article"""
    if not DEV_TO_API_KEY:
        print("❌ CRITICAL ERROR: DEV_TO_API_KEY is missing from GitHub Secrets!")
        return False

    # The EXACT Dev.to API endpoint for creating comments
    url = f"{BASE_URL}/comments"
    
    # Dev.to requires 'api-key', NOT a Bearer token!
    headers = {
        "api-key": DEV_TO_API_KEY,
        "Content-Type": "application/json"
    }
    
    # The payload MUST include commentable_id and commentable_type
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
    print("🐯 Tiger Sentinel: Scanning Dev.to LATEST articles for threats...")
    
    articles = get_latest_articles()
    if not articles:
        print("❌ No articles found. Exiting.")
        return

    for article in articles:
        article_id = article.get("id")
        article_title = article.get("title", "Unknown Title")
        print(f"🔍 Checking article: '{article_title}' (ID: {article_id})")
        
        comments = get_comments_for_article(article_id)
        scam_found = False
        
        for comment in comments:
            body = comment.get("body_markdown", "").lower()
            if any(keyword.lower() in body for keyword in SCAM_KEYWORDS):
                print(f"🚨 SCAM DETECTED on article {article_id}! Deploying counter-measure...")
                scam_found = True
                break
        
        if scam_found:
            post_warning_comment(article_id)
            time.sleep(2)

    print("🐯 Tiger Sentinel: Scan complete. Perimeter secured.")

if __name__ == "__main__":
    main()

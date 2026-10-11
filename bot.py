import os
import requests
import time
import random

API_KEY = os.environ.get("DEV_TO_API_KEY")
HEADERS = {"api-key": API_KEY, "Content-Type": "application/json"}

SCAM_SIGNATURE = "tr.ee/dev-to"
TIGER_REPLY = "THIS IS A PHISHING SCAM 🚨 Do not click this link. Dev.to will never ask you to verify your account via a third-party link in the comments."

def main():
    print("🐯 Tiger Sentinel: Scanning Dev.to for threats...")
    
    response = requests.get("https://dev.to/api/articles?top=3", headers=HEADERS)
    if response.status_code != 200:
        print("❌ Failed to fetch articles.")
        return
        
    articles = response.json()
    
    for article in articles:
        article_id = article['id']
        comments_resp = requests.get(f"https://dev.to/api/comments?a_id={article_id}", headers=HEADERS)
        if comments_resp.status_code != 200:
            continue
            
        comments = comments_resp.json()
        
        for comment in comments:
            if SCAM_SIGNATURE in comment['body_html']:
                bot_replies = [c for c in comments if c.get('user', {}).get('username') == 'watch_dog']
                if len(bot_replies) > 0:
                    print(f"✅ Already neutralized scam on article {article_id}. Skipping.")
                    continue

                print(f" SCAM DETECTED on article {article_id}! Deploying counter-measure...")
                
                payload = {
                    "comment": {
                        "body_markdown": TIGER_REPLY,
                        "commentable_id": article_id,
                        "commentable_type": "Article"
                    }
                }
                
                post_resp = requests.post("https://dev.to/api/comments", json=payload, headers=HEADERS)
                
                if post_resp.status_code == 201:
                    print("✅ Tiger Sentinel successful! Scam neutralized.")
                else:
                    print(f"❌ Failed to post. Status: {post_resp.status_code}")
                
                time.sleep(random.randint(3, 7))

if __name__ == "__main__":
    main()

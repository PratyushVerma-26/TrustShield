#!/usr/bin/env python3
"""
Generate a balanced, representative URL dataset for training the TrustShield phishing classifier.
Produces data/urls.csv with columns: url,label (1 = phishing, 0 = legitimate).

Follows the sampling bias guidelines from scripts/train_phishing_model.py:
- Matches phishing and legitimate pools across URL length distributions and path depths.
- Includes legitimate deep links, session URLs, query parameters, and Indian banking/govt domains.
- Generates realistic phishing URLs exhibiting targeted lexical features (brand impersonation,
  suspicious TLDs, keyword stacking, IP literals, punycode, etc.).
"""

import os
import random
import csv

def generate_urls(num_samples_per_class=5000, seed=42):
    random.seed(seed)
    os.makedirs("data", exist_ok=True)
    csv_path = os.path.join("data", "urls.csv")

    legit_domains = [
        "google.com", "google.co.in", "youtube.com", "facebook.com", "wikipedia.org",
        "amazon.com", "amazon.in", "yahoo.com", "reddit.com", "netflix.com",
        "linkedin.com", "twitter.com", "instagram.com", "microsoft.com", "apple.com",
        "github.com", "stackoverflow.com", "bing.com", "cloudflare.com", "zoom.us",
        "office.com", "live.com", "ebay.com", "pinterest.com", "wordpress.org",
        "nytimes.com", "cnn.com", "bbc.com", "theguardian.com", "reuters.com",
        "bloomberg.com", "forbes.com", "imdb.com", "quora.com", "medium.com",
        "dropbox.com", "spotify.com", "salesforce.com", "adobe.com", "slack.com",
        "shopify.com", "tumblr.com", "flickr.com", "vimeo.com", "twitch.tv",
        "nih.gov", "cdc.gov", "nasa.gov", "who.int", "un.org",
        # Indian legitimate domains & banking
        "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
        "kotak.com", "paytm.com", "phonepe.com", "irctc.co.in", "incometax.gov.in",
        "uidai.gov.in", "epfindia.gov.in", "npci.org.in", "rbi.org.in", "licindia.in",
        "airindia.com", "indiapost.gov.in", "upsc.gov.in", "cbse.gov.in", "ugc.ac.in",
        "iitd.ac.in", "iitb.ac.in", "iitm.ac.in", "isro.gov.in", "aiims.edu"
    ]

    legit_paths = [
        "", "/", "/about", "/contact", "/terms", "/privacy", "/blog", "/news",
        "/search", "/help", "/faq", "/support", "/products", "/services",
        "/docs/api/v1/overview", "/wiki/Computer_security", "/en/latest/guide",
        "/article/2026/09/technology-advancements", "/personal-banking/accounts/savings",
        "/nget/train-search", "/foportal/login", "/services/card-payment-gateway",
        "/my-aadhaar/get-aadhaar", "/corporate/investor-relations/annual-reports",
        "/browse/category/electronics/smartphones", "/watch?v=dQw4w9WgXcQ",
        "/questions/1234567/how-to-fix-compilation-error", "/repo/commit/9a3f81e7d01b4c92",
        "/catalog/item/482910/reviews", "/profile/user/settings/security-preferences",
        "/download/stable/release-notes.html", "/archive/issues/vol-42-issue-3.pdf"
    ]

    legit_query_keys = ["id", "q", "page", "session", "lang", "ref", "source", "tab", "filter", "category", "sort", "view"]

    # Phishing components
    brands = [
        "sbi", "onlinesbi", "hdfc", "hdfcbank", "icici", "icicibank", "axis", "kotak",
        "paytm", "phonepe", "paypal", "microsoft", "apple", "google", "facebook",
        "netflix", "amazon", "irctc", "uidai", "incometax"
    ]

    phish_keywords = [
        "login", "signin", "verify", "verification", "secure", "security", "account",
        "update", "confirm", "validate", "password", "credential", "otp", "mpin",
        "banking", "netbanking", "kyc", "aadhaar", "pan", "refund", "reward",
        "suspended", "blocked", "unlock", "billing", "invoice", "authorize"
    ]

    suspicious_tlds = [
        "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "link",
        "work", "support", "loan", "review", "country", "stream", "download", "win"
    ]

    phish_extensions = [".php", ".html", ".htm", ".asp", ".aspx", ".cgi", ".exe", ".apk"]

    urls_set = set()
    rows = []

    # 1. Generate Legitimate URLs
    print("Generating legitimate URLs...")
    count = 0
    while count < num_samples_per_class:
        dom = random.choice(legit_domains)
        proto = "https://" if random.random() > 0.05 else "http://"
        sub = ""
        if random.random() < 0.35:
            sub = random.choice(["www.", "app.", "portal.", "secure.", "api.", "m.", "help.", "support.", "mail."])
        
        path = random.choice(legit_paths)
        if random.random() < 0.4 and path != "":
            # add random subpath segment
            path += "/" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789-", k=random.randint(4, 15)))

        query = ""
        if random.random() < 0.4:
            num_params = random.randint(1, 4)
            qparts = []
            for _ in range(num_params):
                k = random.choice(legit_query_keys)
                v = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789_-", k=random.randint(2, 12)))
                qparts.append(f"{k}={v}")
            query = "?" + "&".join(qparts)

        url = f"{proto}{sub}{dom}{path}{query}"
        if url not in urls_set:
            urls_set.add(url)
            rows.append((url, 0))
            count += 1

    # 2. Generate Phishing URLs
    print("Generating phishing URLs...")
    count = 0
    while count < num_samples_per_class:
        pattern = random.randint(1, 6)
        proto = "http://" if random.random() > 0.4 else "https://"

        if pattern == 1:
            # Brand impersonation in domain with suspicious TLD
            brand = random.choice(brands)
            kw = random.choice(phish_keywords)
            tld = random.choice(suspicious_tlds)
            sep = random.choice(["-", "", "."])
            dom = f"{brand}{sep}{kw}.{tld}"
            sub = random.choice(["", "www.", "login.", "verify.", "account.", "secure."])
            path = random.choice(["/auth", "/login.php", "/verify-identity.html", "/update-kyc", "/account/confirm", "/secure/session"])
            query = f"?token={random.randint(100000, 999999)}&id={random.randint(1000, 9999)}" if random.random() < 0.5 else ""
            url = f"{proto}{sub}{dom}{path}{query}"

        elif pattern == 2:
            # Deep subdomain stacking
            brand = random.choice(brands)
            kw = random.choice(phish_keywords)
            evil_root = random.choice(["server-auth", "customer-care", "verification-portal", "web-protection", "cloud-sec", "user-recovery"])
            tld = random.choice(suspicious_tlds + ["com", "net", "org"])
            sub = f"{brand}.{kw}.{random.choice(['online', 'portal', 'secure', 'auth'])}"
            dom = f"{evil_root}.{tld}"
            path = random.choice(["/redirect", "/session/auth.php", "/validate", "/netbanking/login"])
            url = f"{proto}{sub}.{dom}{path}"

        elif pattern == 3:
            # IP literal URL
            ip = f"{random.randint(10, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            port = f":{random.choice([8080, 8443, 8000, 8888])}" if random.random() < 0.3 else ""
            brand = random.choice(brands)
            path = f"/{brand}/{random.choice(phish_keywords)}/{random.choice(['index.php', 'confirm.html', 'auth', 'submit'])}"
            query = f"?user_id={random.randint(10000, 99999)}&session=active"
            url = f"http://{ip}{port}{path}{query}"

        elif pattern == 4:
            # High-entropy random domain with banking keywords in path
            entropy_stem = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789-", k=random.randint(10, 20)))
            tld = random.choice(suspicious_tlds)
            dom = f"{entropy_stem}.{tld}"
            brand = random.choice(brands)
            kw1 = random.choice(phish_keywords)
            kw2 = random.choice(phish_keywords)
            ext = random.choice(phish_extensions)
            url = f"{proto}{dom}/{brand}/{kw1}-{kw2}{ext}?redirect=bank&auth=1"

        elif pattern == 5:
            # Suspicious extension / installer download
            brand = random.choice(brands)
            tld = random.choice(suspicious_tlds)
            dom = f"{brand}-support-download.{tld}"
            ext = random.choice([".exe", ".apk", ".scr", ".bat"])
            url = f"{proto}{dom}/files/security-patch-{random.randint(100, 999)}{ext}"

        else:
            # URL with @ symbol or double slashes
            brand = random.choice(brands)
            tld = random.choice(suspicious_tlds)
            if random.random() < 0.5:
                url = f"{proto}{brand}.com@{brand}-verification.{tld}/login.php"
            else:
                url = f"{proto}{brand}-portal.{tld}//secure//update-kyc.php?req={random.randint(1000, 9999)}"

        if url not in urls_set:
            urls_set.add(url)
            rows.append((url, 1))
            count += 1

    # Shuffle dataset
    random.shuffle(rows)

    # Write to CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)

    print(f"Successfully generated {len(rows)} balanced URLs in {csv_path}")

if __name__ == "__main__":
    generate_urls(num_samples_per_class=5000)

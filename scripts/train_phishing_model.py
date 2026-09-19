#!/usr/bin/env python3
"""
Train the TrustShield phishing URL classifier.

Produces `phishing_model.json`, consumed at runtime by
com.trustshield.phishing.ml.PhishingModel.

CRITICAL: the feature extraction below must mirror
UrlFeatureExtractor.java EXACTLY - same features, same order, same logic.
Divergence between training and serving ("training/serving skew") applies
coefficients to the wrong columns and produces confidently wrong verdicts
without any error being raised. To guard against that, this script also writes
`parity_fixtures.json`, which UrlFeatureExtractorParityTest.java loads to assert
the Java extractor produces identical vectors. Run the Java test after every
change to either implementation.

Usage
-----
    pip install pandas scikit-learn numpy
    python train_phishing_model.py --data data/urls.csv

Input CSV must have columns:
    url    - the full URL
    label  - 1 for phishing, 0 for legitimate

Where to get data (all free)
----------------------------
  PhishTank verified phishing feed  https://phishtank.org/developer_info.php
  OpenPhish community feed          https://openphish.com/feed.txt
  Tranco top sites (legitimate)     https://tranco-list.eu/
  UCI phishing dataset              https://archive.ics.uci.edu/dataset/327/
  Kaggle "Malicious URLs dataset"   search: malicious urls dataset

Build a balanced set: take N phishing URLs from PhishTank and N legitimate URLs
from Tranco. Aim for at least 5,000 of each. Class imbalance is handled with
class_weight='balanced' regardless, but a badly skewed set still hurts
calibration.

IMPORTANT on sampling bias: Tranco top sites are overwhelmingly short, HTTPS,
dot-com and well-known, while PhishTank URLs are long and oddly shaped. A model
trained naively on those two pools learns "long URL = phishing" and will
misclassify legitimate deep links (a real bank's 120-character session URL).
Mitigate by including legitimate deep links, not just homepages - see
--legit-deep-links. Report this limitation in the project write-up.
"""

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

try:
    import numpy as np
    import pandas as pd
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                 f1_score, roc_auc_score, confusion_matrix,
                                 classification_report)
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler
except ImportError as exc:
    sys.exit(f"Missing dependency: {exc}\nRun: pip install pandas scikit-learn numpy")


# ---------------------------------------------------------------------------
# Feature definitions - MUST MATCH UrlFeatureExtractor.java
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "url_length",                 # 0
    "host_length",                # 1
    "path_length",                # 2
    "query_length",               # 3
    "num_dots_in_host",           # 4
    "num_hyphens_in_host",        # 5
    "num_subdomains",             # 6
    "num_digits_in_host",         # 7
    "digit_ratio_in_host",        # 8
    "host_entropy",               # 9
    "is_ip_literal",              # 10
    "is_punycode",                # 11
    "has_at_symbol",              # 12
    "has_double_slash_in_path",   # 13
    "is_https",                   # 14
    "has_explicit_port",          # 15
    "num_path_segments",          # 16
    "num_query_params",           # 17
    "num_encoded_chars",          # 18
    "num_sensitive_keywords",     # 19
    "brand_impersonation",        # 20
    "suspicious_tld",             # 21
    "is_shortener",               # 22
    "longest_host_token_len",     # 23
    "num_hyphens_in_url",         # 24
    "has_suspicious_extension",   # 25
]

SENSITIVE_KEYWORDS = {
    "login", "signin", "sign-in", "logon", "verify", "verification",
    "secure", "security", "account", "update", "confirm", "validate",
    "password", "passwd", "credential", "otp", "mpin", "pin",
    "bank", "banking", "netbanking", "upi", "payment", "pay", "wallet",
    "kyc", "aadhaar", "aadhar", "pan", "refund", "reward", "prize",
    "unlock", "suspended", "blocked", "expire", "expired", "recover",
    "invoice", "billing", "transaction", "webscr", "authorize",
}

BRAND_DOMAINS = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"},
    "onlinesbi": {"onlinesbi.sbi", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com", "icici.com"},
    "axis": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "googlepay": {"pay.google.com", "google.com"},
    "bhim": {"npci.org.in", "bhimupi.org.in"},
    "npci": {"npci.org.in"},
    "irctc": {"irctc.co.in", "irctc.com"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "uidai": {"uidai.gov.in"},
    "epfindia": {"epfindia.gov.in"},
    "amazon": {"amazon.com", "amazon.in"},
    "flipkart": {"flipkart.com"},
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "google.co.in"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "netflix": {"netflix.com"},
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "link",
    "work", "support", "loan", "review", "country", "stream", "download",
    "racing", "win", "bid", "date", "faith", "zip", "mov", "rest", "cam",
}

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "bitly.com",
    "s.id", "shorte.st", "adf.ly", "t.ly", "linktr.ee",
}

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".apk", ".scr", ".bat", ".cmd", ".msi", ".dmg", ".jar",
    ".vbs", ".ps1", ".hta", ".iso", ".img",
)

# Public suffixes with open registration: anyone may buy a name under them, so
# membership says nothing about the registrant. co.in belongs here and not in
# VERIFIED_SUFFIXES -- hdfcbank-netbanking.co.in is a purchasable phishing
# domain and must keep scoring as one.
OPEN_SUFFIXES = {
    "co.in", "co.uk", "com.au", "co.jp", "net.in", "org.in",
    "com.br", "co.za", "com.sg", "org.uk", "firm.in", "gen.in",
    "ind.in", "co.nz", "com.my", "com.ph", "co.th", "com.tr", "com.mx",
}

# Public suffixes whose registry verifies the registrant before delegating a
# name, so a brand token under them is evidence of legitimacy rather than
# impersonation. bank.in is restricted by the RBI to licensed Indian banks.
VERIFIED_SUFFIXES = {
    "bank.in", "fin.in",
    "gov.in", "nic.in", "mil.in", "ac.in", "edu.in", "res.in",
    "gov.uk", "ac.uk", "edu.au", "gov.au",
}

VERIFIED_TLDS = {"bank", "insurance", "gov", "mil", "edu"}

TWO_LABEL_SUFFIXES = OPEN_SUFFIXES | VERIFIED_SUFFIXES

# Words attackers glue onto a brand token inside one label. Requiring the
# remainder of a token to be a recognised word is what stops "praxis" matching
# "axis" and "pineapple" matching "apple" while keeping "hdfcbank" caught.
GLUE_WORDS = SENSITIVE_KEYWORDS | {
    "online", "net", "web", "portal", "india", "in", "app", "my", "new",
    "home", "live", "care", "help", "support", "id", "user", "customer",
    "official", "service", "services", "mobile", "www", "co", "corp",
}

IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def shannon_entropy(s: str) -> float:
    """Byte-for-byte mirror of UrlFeatureExtractor.shannonEntropy.

    ASCII only, base 2, and the denominator is the count of *considered*
    (ASCII) characters rather than the full string length. Any divergence from
    the Java version is training/serving skew and will silently degrade
    predictions, which is what UrlFeatureExtractorParityTest exists to catch.

    Note this is a unigram entropy: it is invariant to character order, so it
    measures character diversity, not randomness.
    """
    if not s:
        return 0.0
    counts = {}
    considered = 0
    for ch in s:
        if ord(ch) < 128:
            counts[ch] = counts.get(ch, 0) + 1
            considered += 1
    if considered == 0:
        return 0.0
    entropy = 0.0
    for c in counts.values():
        p = c / considered
        entropy -= p * math.log(p, 2)
    return entropy


def registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = labels[-2] + "." + labels[-1]
    if last_two in TWO_LABEL_SUFFIXES and len(labels) >= 3:
        return labels[-3] + "." + last_two
    return last_two


def public_suffix_label_count(host: str) -> int:
    """Trailing labels belonging to the public suffix, not the registrant.

    Mirror of UrlFeatureExtractor.publicSuffixLabelCount.
    """
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] + "." + labels[-1] in TWO_LABEL_SUFFIXES:
        return 2
    return 1


def is_verified_registry(host: str) -> bool:
    """Mirror of UrlFeatureExtractor.isVerifiedRegistry.

    Reads only the actual trailing suffix, so hdfc.bank.in.evil.tk is not
    exempt: its suffix is tk.
    """
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] + "." + labels[-1] in VERIFIED_SUFFIXES:
        return True
    return len(labels) >= 2 and labels[-1] in VERIFIED_TLDS


def brand_token_present(host: str, brand: str) -> bool:
    """Mirror of UrlFeatureExtractor.brandTokenPresent.

    The brand must fill a whole dot/hyphen token or sit next to a recognised
    word inside one. The former substring test flagged praxis.com and
    pineapple.co as bank impersonation.
    """
    for token in re.split(r"[.\-_]", host):
        if not token:
            continue
        if token == brand:
            return True
        if token.startswith(brand) and token[len(brand):] in GLUE_WORDS:
            return True
        if token.endswith(brand) and token[:-len(brand)] in GLUE_WORDS:
            return True
    return False


def sensitive_keyword_count(lower_url: str, host: str) -> int:
    """Mirror of UrlFeatureExtractor.countSensitiveKeywords.

    Substitutes the registrant part of the host for the host so that "bank" in
    the bank.in suffix is not counted as the registrant using urgency
    vocabulary. Keywords in the path, query and fragment still count.
    """
    haystack = lower_url
    if host:
        idx = haystack.find(host)
        if idx >= 0:
            registrant = ".".join(host.split(".")[:-public_suffix_label_count(host)])
            haystack = haystack[:idx] + registrant + haystack[idx + len(host):]
    return sum(1 for kw in SENSITIVE_KEYWORDS if kw in haystack)


def brand_impersonation(host: str) -> bool:
    if not host:
        return False
    reg = registrable_domain(host)
    for brand, legit_domains in BRAND_DOMAINS.items():
        if not brand_token_present(host, brand):
            continue
        legitimate = any(
            reg == d or host == d or host.endswith("." + d) for d in legit_domains
        )
        if legitimate:
            continue
        # A name inside an accredited registry was vetted before delegation, so
        # the brand token is not evidence of impersonation. This suppresses one
        # signal; every other feature still scores normally.
        if is_verified_registry(host):
            continue
        return True
    return False


def longest_token_length(host: str) -> int:
    tokens = re.split(r"[.\-_]", host)
    return max((len(t) for t in tokens), default=0)


def count_path_segments(path: str) -> int:
    if not path or path == "/":
        return 0
    return sum(1 for seg in path.split("/") if seg)


def extract_features(raw_url: str) -> list:
    """Mirror of UrlFeatureExtractor.extract(). Returns 26 floats in FEATURE_NAMES order."""
    url = (raw_url or "").strip()
    lower = url.lower()

    for_parsing = url if lower.startswith(("http://", "https://")) else "http://" + url
    parsed_https = lower.startswith("https://")

    try:
        parts = urlsplit(for_parsing)
        host = (parts.hostname or "").lower()
        path = parts.path or ""
        query = parts.query or ""
        try:
            explicit_port = parts.port if parts.port else -1
        except ValueError:
            explicit_port = -1
    except ValueError:
        stripped = re.sub(r"^https?://", "", for_parsing)
        slash = stripped.find("/")
        host = stripped if slash < 0 else stripped[:slash]
        path = "" if slash < 0 else stripped[slash:]
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)
        host = host.split(":")[0].lower()
        explicit_port = -1

    num_digits_host = sum(1 for c in host if c.isdigit())
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    f = [0.0] * len(FEATURE_NAMES)
    f[0] = float(len(url))
    f[1] = float(len(host))
    f[2] = float(len(path))
    f[3] = float(len(query))
    f[4] = float(host.count("."))
    f[5] = float(host.count("-"))
    f[6] = float(max(0, host.count(".") - public_suffix_label_count(host)))
    f[7] = float(num_digits_host)
    f[8] = float(num_digits_host / len(host)) if host else 0.0
    f[9] = shannon_entropy(host)
    f[10] = 1.0 if IPV4_RE.match(host) else 0.0
    f[11] = 1.0 if "xn--" in host else 0.0
    f[12] = 1.0 if "@" in url else 0.0
    f[13] = 1.0 if "//" in path else 0.0
    f[14] = 1.0 if parsed_https else 0.0
    f[15] = 1.0 if explicit_port not in (-1, 80, 443) else 0.0
    f[16] = float(count_path_segments(path))
    f[17] = float(len(query.split("&"))) if query else 0.0
    f[18] = float(lower.count("%"))
    f[19] = float(sensitive_keyword_count(lower, host))
    f[20] = 1.0 if brand_impersonation(host) else 0.0
    f[21] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
    f[22] = 1.0 if host in SHORTENER_HOSTS else 0.0
    f[23] = float(longest_token_length(host))
    f[24] = float(url.count("-"))
    f[25] = 1.0 if path.lower().endswith(SUSPICIOUS_EXTENSIONS) else 0.0
    return f


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Train the TrustShield phishing classifier")
    ap.add_argument("--data", required=True,
                    help="CSV with columns: url,label (label 1=phishing, 0=legitimate)")
    ap.add_argument("--out", default="phishing_model.json",
                    help="Output model file")
    ap.add_argument("--fixtures", default="parity_fixtures.json",
                    help="Output parity fixtures for the Java test")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--C", type=float, default=1.0,
                    help="Inverse regularisation strength")
    args = ap.parse_args()

    print(f"Reading {args.data} ...")
    df = pd.read_csv(args.data)
    if "url" not in df.columns or "label" not in df.columns:
        sys.exit(f"CSV must have 'url' and 'label' columns; found {list(df.columns)}")

    df = df.dropna(subset=["url", "label"]).drop_duplicates(subset=["url"])
    df["label"] = df["label"].astype(int)

    n_phish = int((df.label == 1).sum())
    n_legit = int((df.label == 0).sum())
    print(f"  {len(df)} unique rows: {n_phish} phishing, {n_legit} legitimate")
    if n_phish < 200 or n_legit < 200:
        print("  WARNING: fewer than 200 examples in a class. Metrics from this "
              "run will not be trustworthy. Gather more data before reporting.")

    print("Extracting features ...")
    X = np.array([extract_features(u) for u in df["url"]], dtype=float)
    y = df["label"].to_numpy()

    if not np.isfinite(X).all():
        bad = np.argwhere(~np.isfinite(X))
        sys.exit(f"Non-finite feature values at {bad[:10]} - fix extraction before training")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_test_s = scaler.transform(X_test)

    print("Fitting logistic regression ...")
    clf = LogisticRegression(
        C=args.C,
        max_iter=2000,
        class_weight="balanced",
        solver="lbfgs",
    ).fit(X_train_s, y_train)

    y_pred = clf.predict(X_test_s)
    y_prob = clf.predict_proba(X_test_s)[:, 1]

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "rocAuc": round(float(roc_auc_score(y_test, y_prob)), 4),
        "testSetSize": int(len(y_test)),
        "trueNegatives": int(tn),
        "falsePositives": int(fp),
        "falseNegatives": int(fn),
        "truePositives": int(tp),
        "falsePositiveRate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
    }

    cv = cross_val_score(clf, X_train_s, y_train, cv=5, scoring="f1")

    print("\n--- Held-out test results ---")
    print(classification_report(y_test, y_pred,
                                target_names=["legitimate", "phishing"],
                                zero_division=0))
    print(f"ROC-AUC: {metrics['rocAuc']}")
    print(f"False positive rate: {metrics['falsePositiveRate']}")
    print(f"5-fold CV F1 on train: {cv.mean():.4f} +/- {cv.std():.4f}")
    print("\nThese are the ONLY numbers you may quote in the report. "
          "Quote the false positive rate alongside accuracy - for a security "
          "tool a high FPR is what makes users switch it off.")

    print("\n--- Feature coefficients (standardised, descending |value|) ---")
    ranked = sorted(zip(FEATURE_NAMES, clf.coef_[0]), key=lambda t: -abs(t[1]))
    for name, coef in ranked:
        direction = "-> phishing" if coef > 0 else "-> legitimate"
        print(f"  {name:28s} {coef:+.4f}  {direction}")

    model = {
        "_comment": [
            "Generated by train_phishing_model.py. Do not edit by hand.",
            "featureNames order is contractual and is validated at startup",
            "against UrlFeatureExtractor.FEATURE_NAMES.",
        ],
        "version": datetime.now(timezone.utc).strftime("1.0.0-%Y%m%d%H%M"),
        "provenance": "TRAINED",
        "modelType": "logistic_regression",
        "standardisation": "z-score",
        "trainedOn": datetime.now(timezone.utc).isoformat(),
        "trainingRows": int(len(X_train)),
        "featureNames": FEATURE_NAMES,
        "mean": [round(float(v), 8) for v in scaler.mean_],
        "scale": [round(float(v), 8) for v in scaler.scale_],
        "coefficients": [round(float(v), 8) for v in clf.coef_[0]],
        "intercept": round(float(clf.intercept_[0]), 8),
        "metrics": metrics,
        "crossValidation": {
            "folds": 5,
            "scoring": "f1",
            "meanF1": round(float(cv.mean()), 4),
            "stdF1": round(float(cv.std()), 4),
        },
        "dataset": {
            "source": args.data,
            "totalRows": int(len(df)),
            "phishingRows": n_phish,
            "legitimateRows": n_legit,
            "testSize": args.test_size,
            "randomSeed": args.seed,
        },
    }

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(model, fh, indent=2)
    print(f"\nWrote {args.out}")
    print("Copy it to: trustshield-phishing-service/src/main/resources/models/phishing_model.json")

    # Parity fixtures so the Java extractor can be proven equivalent.
    fixture_urls = [
        "https://www.google.com",
        "http://sbi-secure-login.verify-account.xyz/netbanking/login.php",
        "http://192.168.1.1/admin",
        "https://onlinesbi.sbi/personal",
        "http://bit.ly/3xY2z",
        "https://paytm.com/offers",
        "http://paytm.account-verify.tk/upi/confirm?id=99",
        "https://xn--80ak6aa92e.com/login",
        "http://example.com//double//slash/",
        "https://user@evil.example.org/reset",
        "http://download.free-movies.top/setup.exe",
        "https://irctc.co.in/nget/train-search",
        "https://a.b.c.d.e.deep-subdomain-chain.co.in/x",
        "not even a url",
        "",
    ]
    fixtures = {
        "_comment": "Generated by train_phishing_model.py. Loaded by "
                    "UrlFeatureExtractorParityTest to detect training/serving skew.",
        "featureNames": FEATURE_NAMES,
        "cases": [{"url": u, "features": [round(v, 8) for v in extract_features(u)]}
                  for u in fixture_urls],
    }
    with open(args.fixtures, "w", encoding="utf-8") as fh:
        json.dump(fixtures, fh, indent=2)
    print(f"Wrote {args.fixtures}")
    print("Copy it to: trustshield-phishing-service/src/test/resources/parity_fixtures.json")
    print("Then run: mvn test -pl trustshield-phishing-service")


if __name__ == "__main__":
    main()

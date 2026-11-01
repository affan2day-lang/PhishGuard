#!/usr/bin/env python3
"""PhishGuard - a tiny heuristic phishing link detector.

Pure standard library. No network requests: it only inspects the URL string.
This is a learning project, not a security product.
"""
import argparse
import difflib
import ipaddress
import json
import re
import sys
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "support", "rest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
KEYWORDS = ["login", "signin", "verify", "update", "secure", "account", "password",
            "confirm", "banking", "wallet", "suspend", "unlock", "billing", "payment"]
BRANDS = ["paypal", "google", "facebook", "instagram", "apple", "microsoft", "amazon",
          "netflix", "bkash", "nagad", "binance", "dhl", "fedex", "whatsapp", "linkedin"]


def _brand_check(host):
    """Return a brand name if the host looks like a fake of it."""
    labels = re.split(r"[.\-]", host)
    registered = ".".join(host.split(".")[-2:])
    for brand in BRANDS:
        if registered.split(".")[0] == brand:
            continue  # the real domain (e.g. paypal.com)
        if brand in labels or brand in host.replace("-", ""):
            return brand, "contains brand name on a different domain"
        for label in labels:
            if len(label) > 4 and difflib.SequenceMatcher(None, label, brand).ratio() > 0.85:
                return brand, "looks like a misspelling"
    return None


def analyze(url):
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower()
    reasons, score = [], 0

    def flag(points, msg):
        nonlocal score
        score += points
        reasons.append(msg)

    if parsed.scheme != "https":
        flag(10, "Does not use HTTPS")
    try:
        ipaddress.ip_address(host)
        flag(30, "Uses a raw IP address instead of a domain")
    except ValueError:
        pass
    if "@" in parsed.netloc:
        flag(25, "Contains '@' (can hide the real destination)")
    if host.startswith("xn--") or ".xn--" in host:
        flag(20, "Punycode domain (possible lookalike characters)")
    if len(raw) > 75:
        flag(10, "Very long URL")
    if host.count(".") >= 4:
        flag(15, "Too many subdomains")
    if host.count("-") >= 3:
        flag(10, "Many hyphens in domain")
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        flag(15, "Suspicious top-level domain")
    if host in SHORTENERS:
        flag(15, "URL shortener hides the final destination")
    hits = [k for k in KEYWORDS if k in raw.lower()]
    if hits:
        flag(min(5 * len(hits), 20), "Suspicious keywords: " + ", ".join(hits))
    brand = _brand_check(host)
    if brand:
        flag(30, f"Possible '{brand[0]}' impersonation ({brand[1]})")
    if raw.count("//") > 1:
        flag(10, "Extra '//' in URL (possible redirect trick)")

    score = min(score, 100)
    verdict = "DANGEROUS" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LOOKS OK"
    return {"url": raw, "score": score, "verdict": verdict, "reasons": reasons}


def main():
    p = argparse.ArgumentParser(description="Heuristic phishing link detector")
    p.add_argument("urls", nargs="*", help="URLs to check")
    p.add_argument("-f", "--file", help="text file with one URL per line")
    p.add_argument("--json", action="store_true", help="output JSON")
    args = p.parse_args()

    urls = list(args.urls)
    if args.file:
        with open(args.file) as fh:
            urls += [l.strip() for l in fh if l.strip()]
    if not urls:
        p.print_help()
        sys.exit(1)

    results = [analyze(u) for u in urls]
    if args.json:
        print(json.dumps(results, indent=2))
        return
    for r in results:
        print(f"\n{r['url']}\n  {r['verdict']} (risk {r['score']}/100)")
        for reason in r["reasons"]:
            print(f"   - {reason}")


if __name__ == "__main__":
    main()

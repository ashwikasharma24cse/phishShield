from urllib.parse import urlparse
from rapidfuzz import fuzz
import re

def analyze_url(url):

    findings = []
    score = 0

    parsed_url = urlparse(url)

    domain = parsed_url.netloc.lower()
    domain = domain.replace("www.", "")

    # -------------------------
    # Trusted Domains
    # -------------------------

    trusted_domains = [
        "google.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "apple.com",
        "paypal.com",
        "facebook.com",
        "linkedin.com"
    ]

    is_trusted = False

    for trusted in trusted_domains:

        if domain == trusted or domain.endswith("." + trusted):
            is_trusted = True
            break

    # -------------------------
    # Suspicious Keywords
    # -------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "free",
        "gift",
        "bank",
        "secure",
        "update",
        "password"
    ]

    for keyword in suspicious_keywords:

        if keyword in url.lower():

            findings.append(
                f"⚠ Suspicious keyword found: {keyword}"
            )

            score += 10

    # -------------------------
    # Long URL
    # -------------------------

    if len(url) > 150 and not is_trusted:

        findings.append(
            "⚠ Long URL detected on an untrusted domain"
        )

    # -------------------------
    # Too Many Subdomains
    # -------------------------

    if domain.count(".") > 3:

        findings.append(
            "⚠ Too many subdomains"
        )

        score += 10

    # -------------------------
    # Suspicious TLD
    # -------------------------

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".tk"
    ]

    for tld in suspicious_tlds:

        if domain.endswith(tld):

            findings.append(
                f"⚠ Suspicious TLD detected: {tld}"
            )

            score += 15

    # -------------------------
    # IP Address Detection
    # -------------------------

    ip_pattern = r"^\d+\.\d+\.\d+\.\d+$"

    clean_domain = domain.split(":")[0]

    if re.match(ip_pattern, clean_domain):

        findings.append(
            "⚠ URL uses IP address instead of domain name"
        )

        score += 20

    # -------------------------
    # URL Shortener Detection
    # -------------------------

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl"
    ]

    for shortener in shorteners:

        if shortener in domain:

            findings.append(
                "⚠ URL Shortener detected"
            )

            score += 20

    # -------------------------
    # Typosquatting Detection
    # -------------------------

    famous_brands = [
        "amazon",
        "paypal",
        "google",
        "microsoft",
        "facebook",
        "instagram",
        "netflix",
        "apple"
    ]

    base_domain = domain.split(".")[0]

    for brand in famous_brands:

        similarity = fuzz.ratio(
            base_domain,
            brand
        )

        if similarity >= 80 and base_domain != brand:

            findings.append(
                f"⚠ Possible typosquatting detected (looks like {brand})"
            )

            score += 30

            break

    # -------------------------
    # Risk Level
    # -------------------------

    if score > 100:
        score = 100

    if score <= 20:
        risk = "LOW"

    elif score <= 50:
        risk = "MEDIUM"

    else:
        risk = "HIGH"

    return findings, score, risk
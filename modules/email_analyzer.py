
import re
from rapidfuzz import fuzz

from modules.url_analyzer import analyze_url
from modules.whois_checker import get_domain_age
from modules.ssl_checker import check_ssl
from modules.virustotal_checker import check_virustotal


def analyze_email(sender, subject, body):

    findings = []
    score = 0

    sender_domain = ""
    whois_result = {}
    ssl_result = {}
    url_analysis = []

    email_text = (
        subject + " " + body
    ).lower()

    # -------------------------
    # Suspicious Keywords
    # -------------------------

    suspicious_keywords = [
        "urgent",
        "verify",
        "password",
        "bank",
        "login",
        "click here",
        "account suspended",
        "payment",
        "security alert"
    ]

    for keyword in suspicious_keywords:

        if keyword in email_text:

            findings.append(
                f"⚠ Suspicious keyword: {keyword}"
            )

            score += 10

    # -------------------------
    # Sender Domain Analysis
    # -------------------------

    if "@" in sender:

        sender_domain = sender.split("@")[1]

        trusted_brands = [
            "amazon",
            "paypal",
            "google",
            "microsoft",
            "facebook",
            "instagram",
            "apple",
            "netflix"
        ]

        base_domain = sender_domain.split(".")[0]

        clean_domain = (
            base_domain
            .replace("-", "")
            .replace("_", "")
        )

        for brand in trusted_brands:

            similarity = fuzz.partial_ratio(
                clean_domain,
                brand
            )

            if similarity >= 80 and brand not in clean_domain:

                findings.append(
                    f"⚠ Possible sender spoofing ({brand})"
                )

                score += 30

                break

        # -------------------------
        # WHOIS Check
        # -------------------------

        whois_result = get_domain_age(
            f"https://{sender_domain}"
        )

        if "error" in whois_result:

            findings.append(
                "⚠ Sender domain not registered"
            )

            score += 20

        else:

            if (
                "age_days" in whois_result
                and whois_result["age_days"] < 30
            ):

                findings.append(
                    "⚠ Sender domain is very new"
                )

                score += 20

        # -------------------------
        # SSL Check
        # -------------------------

        ssl_result = check_ssl(
            f"https://{sender_domain}"
        )

        if not ssl_result.get(
            "valid",
            False
        ):

            findings.append(
                "⚠ Sender domain SSL invalid"
            )

            score += 15

    # -------------------------
    # Extract URLs
    # -------------------------

    urls = re.findall(
        r'https?://[^\s]+',
        body
    )

    if urls:

        findings.append(
            f"Found {len(urls)} URL(s)"
        )

        for url in urls:

            # -------------------------
            # URL Analysis
            # -------------------------
            
            url_findings, url_score, url_risk = analyze_url(
                url
            )

            findings.extend(
                url_findings
            )

            score += min(
                url_score,
                20
            )
            # -------------------------
            # SSL Check
            # -------------------------

            url_ssl = check_ssl(
                url
            )

            # -------------------------
            # WHOIS Check
            # -------------------------

            url_whois = get_domain_age(
                url
            )


            # -------------------------
            # VirusTotal Check
            # -------------------------

            vt_result = check_virustotal(
                url
            )

            if isinstance(
                vt_result,
                dict
            ):

                malicious = vt_result.get(
                    "malicious",
                    0
                )

                if (
                    isinstance(
                        malicious,
                        int
                    )
                    and malicious > 0
                ):

                    findings.append(
                        "⚠ VirusTotal flagged URL"
                    )

                    score += 20
            
            url_analysis.append({
                "url": url,
                "risk": url_risk,
                "virustotal": vt_result,
                "ssl": url_ssl,
                "whois": url_whois
            })

    # -------------------------
    # Cap Score
    # -------------------------

    if score > 100:
        score = 100

    # -------------------------
    # Risk Level
    # -------------------------

    if score <= 20:
        risk = "LOW"

    elif score <= 50:
        risk = "MEDIUM"

    else:
        risk = "HIGH"

    return {
        "score": score,
        "risk": risk,
        "findings": findings,
        "sender_domain": sender_domain,
        "urls_found": urls,
        "url_analysis": url_analysis,
        "whois": whois_result,
        "ssl": ssl_result
    }

from difflib import SequenceMatcher
from urllib.parse import unquote

from modules.detection_utils import (
    calculate_risk,
    finding_messages,
    make_finding,
    normalize_url,
    score_findings,
)

try:
    from rapidfuzz import fuzz
except ImportError:
    class fuzz:
        @staticmethod
        def ratio(left, right):
            return int(SequenceMatcher(None, left, right).ratio() * 100)

        @staticmethod
        def partial_ratio(left, right):
            if not left or not right:
                return 0
            shorter, longer = sorted((left, right), key=len)
            best = 0
            for index in range(0, len(longer) - len(shorter) + 1):
                candidate = longer[index:index + len(shorter)]
                best = max(best, fuzz.ratio(shorter, candidate))
            return best


TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "apple.com",
    "paypal.com",
    "facebook.com",
    "linkedin.com",
    "instagram.com",
    "netflix.com",
}

BRAND_DOMAINS = {
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "apple": {"apple.com", "icloud.com"},
}

SUSPICIOUS_KEYWORDS = {
    "login": 8,
    "verify": 10,
    "free": 7,
    "gift": 8,
    "bank": 10,
    "secure": 7,
    "update": 8,
    "password": 12,
    "wallet": 10,
    "invoice": 8,
    "support": 6,
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "tk",
    "zip",
    "mov",
    "rest",
    "cam",
    "quest",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
}


def analyze_url(url, structured=False):
    analysis = analyze_url_details(url)
    if structured:
        return analysis
    return analysis["findingMessages"], analysis["score"], analysis["risk"]


def analyze_url_details(url):
    normalized = normalize_url(url)
    findings = []

    for error in normalized.errors:
        findings.append(
            make_finding(
                "validation",
                "High",
                error,
                normalized.original,
                35,
            )
        )

    is_trusted = normalized.registered_domain in TRUSTED_DOMAINS
    inspected_text = f"{normalized.host}{normalized.path}".lower()

    if normalized.scheme == "http":
        findings.append(
            make_finding(
                "transport",
                "Medium",
                "Website uses unencrypted HTTP",
                normalized.scheme,
                15,
            )
        )

    if normalized.is_ip:
        findings.append(
            make_finding(
                "domain",
                "High",
                "URL uses an IP address instead of a domain name",
                normalized.host,
                20,
            )
        )

    if normalized.ip_private:
        findings.append(
            make_finding(
                "domain",
                "High",
                "URL points to a private or local network address",
                normalized.host,
                35,
            )
        )

    if normalized.idn:
        findings.append(
            make_finding(
                "domain",
                "High",
                "Internationalized domain detected; inspect for homograph impersonation",
                normalized.host,
                20,
            )
        )

    for keyword, weight in SUSPICIOUS_KEYWORDS.items():
        if keyword in inspected_text and not is_trusted:
            findings.append(
                make_finding(
                    "content",
                    "Low",
                    f"Suspicious keyword found: {keyword}",
                    keyword,
                    weight,
                )
            )

    if normalized.subdomain.count(".") >= 2 and not is_trusted:
        findings.append(
            make_finding(
                "domain",
                "Medium",
                "Excessive subdomain nesting detected",
                normalized.subdomain,
                12,
            )
        )

    if _has_misleading_brand_subdomain(normalized) and not is_trusted:
        findings.append(
            make_finding(
                "impersonation",
                "High",
                "Brand-like word appears in the subdomain, not the real domain",
                normalized.host,
                25,
            )
        )

    if normalized.suffix in SUSPICIOUS_TLDS and not is_trusted:
        findings.append(
            make_finding(
                "domain",
                "Medium",
                f"Suspicious top-level domain detected: .{normalized.suffix}",
                normalized.suffix,
                12,
            )
        )

    if normalized.registered_domain in SHORTENERS:
        findings.append(
            make_finding(
                "url",
                "Medium",
                "URL shortener detected",
                normalized.registered_domain,
                18,
            )
        )

    if normalized.port and normalized.port not in {80, 443}:
        findings.append(
            make_finding(
                "network",
                "Medium",
                "Non-standard web port detected",
                str(normalized.port),
                10,
            )
        )

    if "%" in normalized.original and unquote(normalized.original) != normalized.original:
        findings.append(
            make_finding(
                "url",
                "Medium",
                "Encoded characters found in URL",
                normalized.original,
                8,
            )
        )

    brand_finding = _detect_typosquatting(normalized, is_trusted)
    if brand_finding:
        findings.append(brand_finding)

    if not findings and normalized.host:
        findings.append(
            make_finding(
                "reputation",
                "Info",
                "No suspicious URL indicators found",
                normalized.host,
                0,
            )
        )

    score = min(100, score_findings(findings))
    risk = calculate_risk(score)

    return {
        "url": normalized.url,
        "inputUrl": normalized.original,
        "host": normalized.host,
        "registeredDomain": normalized.registered_domain,
        "score": score,
        "risk": risk,
        "findings": findings,
        "findingMessages": finding_messages(findings),
        "normalized": {
            "scheme": normalized.scheme,
            "host": normalized.host,
            "registeredDomain": normalized.registered_domain,
            "subdomain": normalized.subdomain,
            "suffix": normalized.suffix,
            "port": normalized.port,
            "idn": normalized.idn,
            "isIp": normalized.is_ip,
            "privateIp": normalized.ip_private,
        },
    }


def _detect_typosquatting(normalized, is_trusted):
    if is_trusted or not normalized.registered_domain:
        return None

    label = normalized.registered_domain.split(".")[0]
    clean_label = label.replace("-", "").replace("_", "")

    for brand, legitimate_domains in BRAND_DOMAINS.items():
        if normalized.registered_domain in legitimate_domains:
            return None

        similarity = fuzz.ratio(clean_label, brand)
        partial = fuzz.partial_ratio(clean_label, brand)
        contains_brand = brand in clean_label and clean_label != brand

        if similarity >= 80 or (contains_brand and partial >= 90):
            return make_finding(
                "impersonation",
                "High",
                f"Possible typosquatting detected; resembles {brand}",
                normalized.registered_domain,
                30,
            )

    return None


def _has_misleading_brand_subdomain(normalized):
    if not normalized.subdomain:
        return False

    subdomain_text = normalized.subdomain.replace("-", "").replace("_", "")
    registered_label = normalized.registered_domain.split(".")[0]

    for brand in BRAND_DOMAINS:
        if brand in subdomain_text and brand not in registered_label:
            return True

    return False

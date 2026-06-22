import re
from concurrent.futures import ThreadPoolExecutor
from difflib import SequenceMatcher
from urllib.parse import urlparse

from modules.detection_utils import (
    calculate_risk,
    finding_messages,
    make_finding,
    normalize_url,
    score_findings,
)
from modules.ssl_checker import check_ssl
from modules.url_analyzer import BRAND_DOMAINS, analyze_url_details
from modules.virustotal_checker import check_virustotal
from modules.whois_checker import get_domain_age

try:
    from rapidfuzz import fuzz
except ImportError:
    class fuzz:
        @staticmethod
        def partial_ratio(left, right):
            if not left or not right:
                return 0
            shorter, longer = sorted((left, right), key=len)
            best = 0
            for index in range(0, len(longer) - len(shorter) + 1):
                candidate = longer[index:index + len(shorter)]
                best = max(
                    best,
                    int(SequenceMatcher(None, shorter, candidate).ratio() * 100),
                )
            return best


SUSPICIOUS_EMAIL_PHRASES = {
    "urgent": 8,
    "verify": 10,
    "password": 12,
    "bank": 10,
    "login": 8,
    "click here": 8,
    "account suspended": 18,
    "payment": 8,
    "security alert": 12,
    "unusual activity": 12,
    "confirm your identity": 15,
    "limited time": 8,
}

URL_PATTERN = re.compile(r"https?://[^\s<>'\")]+", re.IGNORECASE)
HTML_LINK_PATTERN = re.compile(
    r"<a\s+[^>]*href=[\"'](?P<href>https?://[^\"']+)[\"'][^>]*>(?P<text>.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)

# Max URLs to fully enrich (SSL + WHOIS + VT) to avoid excessive API calls
_MAX_ENRICHED_URLS = 10


def analyze_email(sender, subject, body, html=""):
    findings = []
    sender_domain = _extract_sender_domain(sender)
    email_text = f"{subject or ''} {body or ''}".lower()

    for phrase, weight in SUSPICIOUS_EMAIL_PHRASES.items():
        if phrase in email_text:
            findings.append(
                make_finding(
                    "email-language",
                    "Low" if weight < 12 else "Medium",
                    f"Suspicious email phrase: {phrase}",
                    phrase,
                    weight,
                )
            )

    # Merge plain-text URLs with hrefs from HTML, deduplicated
    urls = _extract_urls(body or "")
    seen_urls = set(urls)
    for href in _extract_href_urls(html or ""):
        if href not in seen_urls:
            seen_urls.add(href)
            urls.append(href)

    # Local heuristic analysis is fast — run before I/O
    enrichable_urls = urls[:_MAX_ENRICHED_URLS]
    url_heuristics = [(url, analyze_url_details(url)) for url in enrichable_urls]

    # Fire all external I/O concurrently in one pool
    futures = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        if sender_domain:
            futures["s_ssl"]   = pool.submit(check_ssl,          f"https://{sender_domain}")
            futures["s_whois"] = pool.submit(get_domain_age,     f"https://{sender_domain}")
            futures["s_vt"]    = pool.submit(check_virustotal,   f"https://{sender_domain}")
        for url, _ in url_heuristics:
            futures[f"ssl:{url}"]   = pool.submit(check_ssl,        url)
            futures[f"whois:{url}"] = pool.submit(get_domain_age,   url)
            futures[f"vt:{url}"]    = pool.submit(check_virustotal, url)
    # All futures are resolved after the with block exits

    sender_ssl   = futures["s_ssl"].result()   if sender_domain else None
    sender_whois = futures["s_whois"].result() if sender_domain else None
    sender_vt    = futures["s_vt"].result()    if sender_domain else None

    if sender_domain:
        findings.extend(_build_sender_findings(sender_domain, sender_ssl, sender_whois))

    link_mismatch_findings = _detect_link_mismatch(html or body or "")
    findings.extend(link_mismatch_findings)

    url_analysis = []
    if urls:
        findings.append(
            make_finding(
                "email-url",
                "Info",
                f"Found {len(urls)} unique URL(s)",
                str(len(urls)),
                0,
            )
        )

    for url, heuristic_analysis in url_heuristics:
        ssl_result   = futures[f"ssl:{url}"].result()
        whois_result = futures[f"whois:{url}"].result()
        vt_result    = futures[f"vt:{url}"].result()

        enriched = _build_enriched_url(heuristic_analysis, ssl_result, whois_result, vt_result)
        url_analysis.append(enriched)

        vt_finding = enriched.get("vtFinding")
        if vt_finding:
            findings.append(vt_finding)

        for url_finding in heuristic_analysis["findings"]:
            if url_finding.get("severity") == "Info":
                continue
            copied = dict(url_finding)
            copied["category"] = f"linked-{copied.get('category', 'url')}"
            copied["scoreImpact"] = min(int(copied.get("scoreImpact", 0) or 0), 20)
            findings.append(copied)

    score = min(100, score_findings(findings))
    risk = calculate_risk(score)

    return {
        "score": score,
        "risk": risk,
        "findings": findings,
        "findingMessages": finding_messages(findings),
        "sender_domain": sender_domain,
        "senderDomain": sender_domain,
        "registeredDomain": sender_domain,
        "ssl": sender_ssl,
        "whois": sender_whois,
        "virustotal": sender_vt,
        "urls_found": urls,
        "urlsFound": urls,
        "url_analysis": url_analysis,
        "urlAnalysis": url_analysis,
    }


def _extract_sender_domain(sender):
    if not sender or "@" not in sender:
        return ""
    domain = sender.rsplit("@", 1)[1].strip().strip(">").lower()
    return normalize_url(f"https://{domain}").registered_domain or domain


def _build_sender_findings(sender_domain, ssl_result, whois_result):
    """Generate findings from pre-fetched sender domain data."""
    findings = []
    label = sender_domain.split(".")[0].replace("-", "").replace("_", "")

    for brand, legitimate_domains in BRAND_DOMAINS.items():
        if sender_domain in legitimate_domains:
            continue
        similarity = fuzz.partial_ratio(label, brand)
        if similarity >= 85 and brand not in sender_domain:
            findings.append(
                make_finding(
                    "sender",
                    "High",
                    f"Possible sender impersonation of {brand}",
                    sender_domain,
                    28,
                )
            )
            break

    if "error" in whois_result:
        findings.append(
            make_finding(
                "sender-domain",
                "Medium",
                "Sender domain age could not be verified",
                whois_result.get("error", sender_domain),
                8,
            )
        )
    elif whois_result.get("age_days", 999999) < 30:
        findings.append(
            make_finding(
                "sender-domain",
                "High",
                "Sender domain is very new",
                f"{whois_result.get('age_days')} days",
                20,
            )
        )

    if not ssl_result.get("valid", False):
        findings.append(
            make_finding(
                "sender-ssl",
                "Low",
                "Sender domain SSL could not be verified",
                ssl_result.get("error", sender_domain),
                6,
            )
        )

    return findings


def _build_enriched_url(analysis, ssl_result, whois_result, vt_result):
    """Build enriched URL result dict from pre-fetched external data."""
    malicious = 0
    suspicious = 0
    vt_score = 0
    if isinstance(vt_result, dict):
        malicious = int(vt_result.get("malicious", 0) or 0)
        suspicious = int(vt_result.get("suspicious", 0) or 0)
        vt_score = min(100, (malicious * 20) + (suspicious * 8))

    vt_finding = None
    if vt_score > 0:
        vt_finding = make_finding(
            "reputation",
            "High" if malicious > 0 else "Medium",
            (
                f"VirusTotal flagged linked URL ({malicious} engines)"
                if malicious > 0
                else f"VirusTotal marked linked URL suspicious ({suspicious} engines)"
            ),
            f"malicious={malicious}, suspicious={suspicious}",
            vt_score,
        )

    return {
        "url": analysis["url"],
        "risk": analysis["risk"],
        "score": analysis["score"],
        "vtScore": vt_score,
        "findings": analysis["findings"],
        "findingMessages": analysis["findingMessages"],
        "virustotal": vt_result,
        "ssl": ssl_result,
        "whois": whois_result,
        "vtFinding": vt_finding,
    }


def _extract_urls(body):
    seen = set()
    urls = []
    for match in URL_PATTERN.findall(body):
        cleaned = match.rstrip(".,;:!?)]}")
        if cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)
    return urls


def _extract_href_urls(html):
    seen = set()
    urls = []
    for match in HTML_LINK_PATTERN.finditer(html):
        href = match.group("href").rstrip(".,;:!?)]}")
        if href and href not in seen:
            seen.add(href)
            urls.append(href)
    return urls


def _detect_link_mismatch(body):
    findings = []
    for match in HTML_LINK_PATTERN.finditer(body):
        href = match.group("href")
        text = re.sub(r"<[^>]+>", "", match.group("text")).strip()
        if not text.startswith("http"):
            continue

        href_host = normalize_url(href).registered_domain
        text_host = normalize_url(text).registered_domain
        if href_host and text_host and href_host != text_host:
            findings.append(
                make_finding(
                    "email-link",
                    "High",
                    "Link text domain does not match the actual destination",
                    f"{text_host} -> {href_host}",
                    25,
                )
            )
    return findings

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


RISK_THRESHOLDS = (
    (20, "LOW"),
    (50, "MEDIUM"),
)

COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "co.in",
    "com.au",
    "com.br",
    "com.cn",
    "co.jp",
    "co.nz",
}

TRACKING_PARAMS_PREFIXES = ("utm_",)
TRACKING_PARAMS = {
    "fbclid",
    "gclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
}


@dataclass
class NormalizedUrl:
    original: str
    url: str
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    registered_domain: str
    subdomain: str
    suffix: str
    is_ip: bool
    ip_private: bool
    idn: bool
    errors: List[str]


def make_finding(
    category: str,
    severity: str,
    message: str,
    evidence: str = "",
    score_impact: int = 0,
) -> Dict[str, object]:
    return {
        "category": category,
        "severity": severity,
        "message": message,
        "evidence": evidence,
        "scoreImpact": score_impact,
    }


def calculate_risk(score: int) -> str:
    score = max(0, min(100, score))
    if score <= RISK_THRESHOLDS[0][0]:
        return RISK_THRESHOLDS[0][1]
    if score <= RISK_THRESHOLDS[1][0]:
        return RISK_THRESHOLDS[1][1]
    return "HIGH"


def score_findings(findings: Iterable[Dict[str, object]]) -> int:
    total = sum(int(finding.get("scoreImpact", 0) or 0) for finding in findings)
    return min(max(total, 0), 100)


def normalize_url(raw_url: str) -> NormalizedUrl:
    original = (raw_url or "").strip()
    errors: List[str] = []

    if original and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original):
        original_for_parse = "https://" + original
    else:
        original_for_parse = original

    parsed = urlparse(original_for_parse)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or ""
    query = parsed.query or ""

    if scheme not in {"http", "https"}:
        errors.append("URL must use http or https")

    if not host:
        errors.append("URL host is missing")

    ascii_host = host.lower().strip(".")
    idn = False
    try:
        ascii_host = ascii_host.encode("idna").decode("ascii")
        idn = ascii_host != host.lower().strip(".")
    except UnicodeError:
        errors.append("URL contains an invalid internationalized domain")

    filtered_query = [
        (key, value)
        for key, value in parse_qsl(query, keep_blank_values=True)
        if key not in TRACKING_PARAMS
        and not any(key.startswith(prefix) for prefix in TRACKING_PARAMS_PREFIXES)
    ]
    clean_query = urlencode(filtered_query, doseq=True)

    netloc = ascii_host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{ascii_host}:{port}"

    clean_url = urlunparse((scheme, netloc, path or "/", "", clean_query, ""))
    domain_parts = split_registered_domain(ascii_host)

    is_ip = False
    ip_private = False
    try:
        ip_value = ipaddress.ip_address(ascii_host)
        is_ip = True
        ip_private = (
            ip_value.is_private
            or ip_value.is_loopback
            or ip_value.is_link_local
            or ip_value.is_reserved
        )
    except ValueError:
        pass

    return NormalizedUrl(
        original=raw_url or "",
        url=clean_url,
        scheme=scheme,
        host=ascii_host,
        port=port,
        path=path,
        query=query,
        registered_domain=domain_parts["registered_domain"],
        subdomain=domain_parts["subdomain"],
        suffix=domain_parts["suffix"],
        is_ip=is_ip,
        ip_private=ip_private,
        idn=idn,
        errors=errors,
    )


def split_registered_domain(host: str) -> Dict[str, str]:
    if not host or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return {"registered_domain": host, "subdomain": "", "suffix": ""}

    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return {"registered_domain": host, "subdomain": "", "suffix": ""}

    suffix_len = 2 if ".".join(labels[-2:]) in COMMON_SECOND_LEVEL_SUFFIXES else 1
    domain_start = max(0, len(labels) - suffix_len - 1)
    registered_domain = ".".join(labels[domain_start:])
    subdomain = ".".join(labels[:domain_start])
    suffix = ".".join(labels[-suffix_len:])

    return {
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "suffix": suffix,
    }


def finding_messages(findings: Iterable[Dict[str, object]]) -> List[str]:
    return [str(finding.get("message", "")) for finding in findings if finding.get("message")]

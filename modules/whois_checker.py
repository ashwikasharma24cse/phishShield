from urllib.parse import urlparse
from datetime import datetime, timezone

try:
    import whois
except ImportError:
    whois = None


def get_domain_age(url):
    if whois is None:
        return {
            "error": "python-whois package is not installed"
        }

    try:

        domain = urlparse(url).netloc
        domain = domain.replace("www.", "")

        info = whois.whois(domain)

        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {
                "error": "Creation date not found"
            }

        now = datetime.now(timezone.utc)

        age_days = (now - creation_date).days   

        return {
            "domain": domain,
            "creation_date": creation_date.strftime("%Y-%m-%d"),
            "age_days": age_days
        }

    except Exception as e:

        return {
            "error": _short_error(e)
        }


def _short_error(error):
    message = str(error).strip()
    if not message:
        return "WHOIS lookup failed"
    first_line = message.splitlines()[0].strip()
    if len(first_line) > 180:
        return first_line[:177] + "..."
    return first_line

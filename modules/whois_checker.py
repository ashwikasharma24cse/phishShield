import whois
from urllib.parse import urlparse
from datetime import datetime, timezone


def get_domain_age(url):

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
            "error": str(e)
        }
import base64
import os
import time

try:
    from dotenv import load_dotenv
    # Anchor to the project root (one level up from this module) so the .env is
    # found regardless of the process's current working directory.
    _ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    load_dotenv(_ENV_PATH)
except ImportError:
    pass

try:
    import requests
except ImportError:
    requests = None

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


def check_virustotal(url):
    if requests is None:
        return {
            "error": "requests package is not installed"
        }

    if not API_KEY:
        return {
            "error": "VIRUSTOTAL_API_KEY is not set; add it to your .env file"
        }

    headers = {
        "x-apikey": API_KEY
    }

    # URL ID encoding required by VirusTotal
    url_id = base64.urlsafe_b64encode(
       url.encode()
    ).decode().strip("=")

    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:

        response = requests.get(
        vt_url,
        headers=headers,
        timeout=8
        )

        if response.status_code == 404:

            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={
                "url": url
                },
                timeout=8
            )

            if submit_response.status_code != 200:

                return {
                    "error":
                    f"Submit failed {submit_response.status_code}"
                }

            analysis_id = (
                submit_response
                .json()["data"]["id"]
            )

            time.sleep(5)

            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=8
            )

            if analysis_response.status_code != 200:

                return {
                    "error":
                    "Analysis fetch failed"
                }

            analysis_data = (
                analysis_response.json()
            )

            stats = (
                analysis_data["data"]
                ["attributes"]
                ["stats"]
            )

            return {
                "malicious":
                stats["malicious"],

                "suspicious":
                stats["suspicious"],

                "harmless":
                stats["harmless"],

                "undetected":
                stats["undetected"],

                "message":
                "Fresh VirusTotal scan"
            }

        elif response.status_code != 200:

            return {
                "error": f"VirusTotal Error {response.status_code}"
                }

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"],
            "undetected": stats["undetected"]
            }

    except Exception as e:

        return {
            "error": str(e)
            }

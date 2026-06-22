import requests
import base64
import time

API_KEY = "0fed0e065ea6a937b47f28af0c1a929f084e296ac74628ef0c458c3e2b2b7179"


def check_virustotal(url):

    headers = {
        "x-apikey": "0fed0e065ea6a937b47f28af0c1a929f084e296ac74628ef0c458c3e2b2b7179"
    }

    # URL ID encoding required by VirusTotal
    url_id = base64.urlsafe_b64encode(
       url.encode()
    ).decode().strip("=")

    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:

        response = requests.get(
        vt_url,
        headers=headers
        )

        if response.status_code == 404:

            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={
                "url": url
                }
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
                headers=headers
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
from flask import Flask, render_template, request,jsonify
import validators
from flask_cors import CORS

from modules.url_analyzer import analyze_url
from modules.virustotal_checker import check_virustotal
from modules.whois_checker import get_domain_age
from modules.ssl_checker import check_ssl
from modules.email_analyzer import analyze_email
from modules.pdf_generator import generate_report
from flask import send_file
from modules.email_analyzer import analyze_email 
import os

app = Flask(__name__)
CORS(app)
latest_report_data = {}

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    findings = []
    score = 0
    risk = ""
    url = ""
    vt_result = None
    ssl_result = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url == "":
            return render_template(
                "index.html",
                result=None
            )

        # Add https:// if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Validate URL
        if validators.url(url):

            findings, score, risk = analyze_url(url)

            vt_result = check_virustotal(url)
            # VirusTotal scoring

            if isinstance(vt_result, dict):

                malicious = vt_result.get(
                    "malicious",
                    0
                )

                suspicious = vt_result.get(
                    "suspicious",
                    0
                )

                if malicious > 0:

                    findings.append(
                        f"⚠ VirusTotal flagged URL ({malicious} engines)"
                    )

                    score += 50

                elif suspicious > 0:

                    findings.append(
                        f"⚠ VirusTotal suspicious ({suspicious} engines)"
                    )

                    score += 25
            whois_result = get_domain_age(url)
            ssl_result = check_ssl(url)

            print("SSL:", ssl_result)

            print("WHOIS:", whois_result)

            # Debug output
            print("VirusTotal Result:", vt_result)

            result = {
                "status": "Valid URL",
                "url": url,
                "score": score,
                "risk": risk,
                "findings": findings
            }
            global latest_report_data

            latest_report_data = {
            "result": result,
            "vt_result": vt_result,
            "whois_result": whois_result,
            "ssl_result": ssl_result
            }

        else:

            result = {
                "status": "Invalid URL",
                "url": url,
                "score": 0,
                "risk": "N/A",
                "findings": []
            }

    return render_template(
        "index.html",
        result=result,
        findings=findings,
        score=score,
        risk=risk,
        url=url,
        vt_result=vt_result,
        whois_result=whois_result,
        ssl_result=ssl_result
    )

@app.route("/download-report")
def download_report():

    report_path = "reports/report.pdf"

    generate_report(
        report_path,
        latest_report_data["result"],
        latest_report_data["vt_result"],
        latest_report_data["whois_result"],
        latest_report_data["ssl_result"]
    )

    return send_file(
        report_path,
        as_attachment=True
    )

@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():

    data = request.get_json()

    url = data.get(
        "url",
        ""
    )

    findings, score, risk = analyze_url(
        url
    )

    vt_result = check_virustotal(
        url
    )
    if isinstance(vt_result, dict):

        malicious = vt_result.get(
            "malicious",
            0
        )

        suspicious = vt_result.get(
            "suspicious",
            0
        )

        if malicious >= 3:

            findings.append(
                f"⚠ VirusTotal flagged URL ({malicious} engines)"
            )

            score += 75

        elif malicious > 0:

            findings.append(
                f"⚠ VirusTotal flagged URL ({malicious} engines)"
            )

            score += 50

        elif suspicious > 0:

            findings.append(
                f"⚠ VirusTotal suspicious ({suspicious} engines)"
            )

            score += 25

    # Recalculate risk
    if score > 100:
        score = 100

    if score <= 20:
        risk = "LOW"

    elif score <= 50:
        risk = "MEDIUM"

    else:
        risk = "HIGH"

    whois_result = get_domain_age(
        url
    )

    ssl_result = check_ssl(url)

    return jsonify({
        "score": score,
        "risk": risk,
        "findings": findings,
        "virustotal": vt_result,
        "whois": whois_result,
        "ssl": ssl_result
    })

@app.route("/api/scan-email", methods=["POST"])
def api_scan_email():

    data = request.get_json(silent=True)

    print("EMAIL DATA RECEIVED:")
    print(data)

    if not data:
        return jsonify({
            "error": "No JSON received"
        }), 400

    sender = data.get("sender", "")
    subject = data.get("subject", "")
    body = data.get("body", "")

    result = analyze_email(
        sender,
        subject,
        body
    )

    return jsonify(result)
    


if __name__ == "__main__":
    app.run(debug=True)
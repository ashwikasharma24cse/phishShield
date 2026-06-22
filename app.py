from flask import Flask, render_template, request,jsonify
import validators
from flask_cors import CORS

from modules.detection_utils import calculate_risk, finding_messages, make_finding, score_findings
from modules.url_analyzer import analyze_url, analyze_url_details
from modules.virustotal_checker import check_virustotal
from modules.whois_checker import get_domain_age
from modules.ssl_checker import check_ssl
from modules.email_analyzer import analyze_email
from modules.pdf_generator import generate_report
from flask import send_file
import os

app = Flask(__name__)
CORS(app)
latest_report_data = {}


def apply_provider_findings(analysis, vt_result):
    findings = list(analysis["findings"])
    vt_score = 0

    if isinstance(vt_result, dict):
        malicious = int(vt_result.get("malicious", 0) or 0)
        suspicious = int(vt_result.get("suspicious", 0) or 0)

        # VT is the primary score driver; tiers ensure any malicious detection → HIGH
        if malicious >= 5:
            vt_score = 90
        elif malicious >= 3:
            vt_score = 80
        elif malicious >= 1:
            vt_score = 60  # always HIGH (threshold is 50)
        elif suspicious >= 3:
            vt_score = 50  # borderline HIGH
        elif suspicious >= 1:
            vt_score = 30  # MEDIUM
        else:
            vt_score = 0

        if malicious > 0:
            findings.append(
                make_finding(
                    "reputation",
                    "High",
                    f"VirusTotal flagged URL ({malicious} engines)",
                    str(malicious),
                    vt_score,
                )
            )
        elif suspicious > 0:
            findings.append(
                make_finding(
                    "reputation",
                    "Medium",
                    f"VirusTotal marked URL suspicious ({suspicious} engines)",
                    str(suspicious),
                    vt_score,
                )
            )
    elif vt_result:
        findings.append(
            make_finding(
                "reputation",
                "Info",
                "VirusTotal result unavailable",
                str(vt_result),
                0,
            )
        )

    heuristic_findings = [
        finding for finding in findings
        if finding.get("category") != "reputation"
    ]
    heuristic_score = score_findings(heuristic_findings)
    if vt_score > 0:
        # Heuristics add up to 15 points on top of the VT-driven base
        score = min(100, vt_score + min(heuristic_score, 15))
    else:
        score = heuristic_score
    risk = calculate_risk(score)
    analysis["findings"] = findings
    analysis["findingMessages"] = finding_messages(findings)
    analysis["score"] = score
    analysis["risk"] = risk
    analysis["vtScore"] = vt_score
    return analysis


def scan_url(url):
    analysis = analyze_url_details(url)
    vt_result = check_virustotal(analysis["url"])
    whois_result = get_domain_age(analysis["url"])
    ssl_result = check_ssl(analysis["url"])
    analysis = apply_provider_findings(analysis, vt_result)

    return {
        "status": "Valid URL" if not analysis["normalized"]["privateIp"] else "Review URL",
        "url": analysis["url"],
        "inputUrl": analysis["inputUrl"],
        "host": analysis["host"],
        "registeredDomain": analysis["registeredDomain"],
        "score": min(100, analysis["score"]),
        "vtScore": min(100, analysis.get("vtScore", 0)),
        "risk": analysis["risk"],
        "findings": analysis["findings"],
        "findingMessages": analysis["findingMessages"],
        "virustotal": vt_result,
        "whois": whois_result,
        "ssl": ssl_result,
        "normalized": analysis["normalized"],
    }

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    findings = []
    score = 0
    risk = ""
    url = ""
    vt_result = None
    ssl_result = None
    whois_result = None

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

            result = scan_url(url)
            findings = result["findingMessages"]
            score = result["score"]
            risk = result["risk"]
            vt_result = result["virustotal"]
            whois_result = result["whois"]
            ssl_result = result["ssl"]
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

    if "result" not in latest_report_data:
        return jsonify({
            "error": "No report data available. Run a web scan first."
        }), 400

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

    data = request.get_json(silent=True) or {}

    url = data.get(
        "url",
        ""
    ).strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = scan_url(url)
    return jsonify(result)

@app.route("/api/scan-email", methods=["POST"])
def api_scan_email():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "No JSON received"
        }), 400

    sender = data.get("sender", "")
    subject = data.get("subject", "")
    body = data.get("body", "")
    html = data.get("html", "")

    result = analyze_email(
        sender,
        subject,
        body,
        html
    )

    return jsonify(result)
    


if __name__ == "__main__":
    app.run(debug=True)

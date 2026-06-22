from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_report(
    filename,
    result,
    vt_result,
    whois_result,
    ssl_result
):

    pdf = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "PhishShield Security Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            f"URL: {result['url']}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Threat Score: {result['score']}/100",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Risk Level: {result['risk']}",
            styles["BodyText"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            "VirusTotal Analysis",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            f"Malicious: {vt_result.get('malicious')}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Suspicious: {vt_result.get('suspicious')}",
            styles["BodyText"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            "Domain Information",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            f"Domain: {whois_result.get('domain')}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Created: {whois_result.get('creation_date')}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Age: {whois_result.get('age_days')} days",
            styles["BodyText"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            "SSL Status",
            styles["Heading2"]
        )
    )

    ssl_status = "Valid" if ssl_result.get("valid") else "Invalid"

    content.append(
        Paragraph(
            f"SSL Certificate: {ssl_status}",
            styles["BodyText"]
    )
)  

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            "Findings",
            styles["Heading2"]
        )
    )

    findings = result.get("findingMessages") or result.get("findings", [])

    for finding in findings:
        if isinstance(finding, dict):
            finding_text = finding.get("message", "")
        else:
            finding_text = finding

        content.append(
            Paragraph(
                finding_text,
                styles["BodyText"]
            )
        )
    content.append(
    Paragraph(
        "Recommendation",
        styles["Heading2"]
        )
    )

    if result["risk"] == "HIGH":

        recommendation = (
        "Avoid visiting this website. "
        "Multiple phishing indicators detected."
        )

    elif result["risk"] == "MEDIUM":

        recommendation = (
        "Proceed with caution. "
        "Some suspicious indicators detected."
        )

    else:

        recommendation = (
        "No major threats detected."
        )

    content.append(
        Paragraph(
            recommendation,
            styles["BodyText"]
        )
    )
    pdf.build(content)

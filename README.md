# PhishShield

PhishShield is a phishing detection toolkit that analyzes **websites** and **emails** for phishing indicators. It combines local heuristics (URL structure, typosquatting, suspicious keywords, SSL, domain age) with the **VirusTotal** reputation API to produce a threat score and risk level.

It ships in two parts:

- **Flask backend** — a REST API + web UI that performs the actual analysis.
- **Chrome extension** — a popup that scans the current website or the open Gmail message by calling the local backend.

---

## Features

- **Website scanning** — URL normalization, IP/private-address detection, suspicious TLDs, URL shorteners, typosquatting/brand-impersonation detection, encoded-character checks, SSL certificate validation, and WHOIS domain-age lookups.
- **Email scanning** — sender-domain impersonation, suspicious phrases, link text vs. destination mismatch, and full reputation enrichment (SSL + WHOIS + VirusTotal) for the sender and every link found in the message body/HTML.
- **VirusTotal-first scoring** — VirusTotal reputation is the primary driver of the threat score; local heuristics adjust it within a capped range. Scores are clamped to a 0–100 range.
- **Parallel I/O** — email scans fan out all external lookups concurrently for fast responses.
- **PDF reports** — generate a downloadable report for a website scan.
- **Chrome extension** — one-click scanning of the active tab or open Gmail message, with a clear "backend not running" message when the Flask server is offline.

---

## Project structure

```
phishShield/
├── app.py                       # Flask app: web UI + /api/scan-url + /api/scan-email
├── modules/
│   ├── detection_utils.py       # URL normalization, scoring, risk thresholds
│   ├── url_analyzer.py          # Website heuristic analysis
│   ├── email_analyzer.py        # Email analysis (parallel enrichment)
│   ├── virustotal_checker.py    # VirusTotal API client (reads key from .env)
│   ├── whois_checker.py         # Domain-age lookups
│   ├── ssl_checker.py           # SSL certificate validation
│   └── pdf_generator.py         # PDF report generation
├── extension/                   # Chrome (Manifest V3) extension
│   ├── manifest.json
│   ├── popup.html / popup.js / popup.css
│   └── content.js               # Gmail content script (extracts sender/subject/body)
├── templates/index.html         # Web UI
├── static/style.css
├── requirements.txt
├── .env.example                 # Template for required environment variables
└── .gitignore
```

---

## Prerequisites

- Python 3.9+
- A free [VirusTotal API key](https://www.virustotal.com/gui/my-apikey)
- Google Chrome (for the extension)

---

## Setup

### 1. Clone and create a virtual environment

```bash
git clone https://github.com/ashwikasharma24cse/phishShield
cd phishShield
python3 -m venv .venv
source .venv/bin/activate        # On Windows: .venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure your VirusTotal API key

Copy the example file and add your key:

```bash
cp .env.example .env
```

Then edit `.env`:

```
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

> `.env` is git-ignored and never committed. Never commit your real API key.

### 4. Run the backend

```bash
python app.py
```

The server starts on **http://127.0.0.1:5000**. Open it in a browser to use the web UI, or leave it running for the Chrome extension.

---

## Using the Chrome extension

1. Make sure the Flask backend is running on `http://127.0.0.1:5000`.
2. Open `chrome://extensions` in Chrome.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the `extension/` folder.
5. Pin the PhishShield icon and click it:
   - On any website → click **Website** to scan the current page.
   - On an open Gmail message → click **Email** to scan the sender and links.

> After editing the extension's `content.js`, click **Reload** on the extension and refresh the Gmail tab for changes to take effect.

---

## API reference

The backend exposes two JSON endpoints (used by the extension):

### `POST /api/scan-url`

```bash
curl -X POST http://127.0.0.1:5000/api/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Returns the threat `score`, `risk`, `vtScore`, `findings`, and raw `virustotal` / `ssl` / `whois` data.

### `POST /api/scan-email`

```bash
curl -X POST http://127.0.0.1:5000/api/scan-email \
  -H "Content-Type: application/json" \
  -d '{"sender": "hello@example.com", "subject": "...", "body": "...", "html": "..."}'
```

Returns the same scoring structure plus sender domain reputation and per-link analysis.

### Web UI / reports

- `GET /` — web interface for scanning a URL.
- `GET /download-report` — downloads a PDF of the most recent website scan.

---

## Scoring & risk levels

The threat score (0–100) maps to a risk level:

| Score   | Risk     |
|---------|----------|
| 0–20    | LOW      |
| 21–50   | MEDIUM   |
| 51–100  | HIGH     |

VirusTotal detections drive the score: any malicious engine detection pushes the result into the **HIGH** range, with local heuristics adding a capped adjustment on top.

---

## Security note

If you ever exposed a VirusTotal API key in a public commit, **rotate it** at the VirusTotal dashboard. Keys belong only in your local `.env` file.

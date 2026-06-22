const API_BASE = "http://127.0.0.1:5000";

const resultEl = document.getElementById("result");
const statusPill = document.getElementById("statusPill");
const activeTarget = document.getElementById("activeTarget");
const scanBtn = document.getElementById("scanBtn");
const emailBtn = document.getElementById("emailBtn");

scanBtn.addEventListener("click", scanCurrentWebsite);
emailBtn.addEventListener("click", scanCurrentEmail);

bootstrap();

async function bootstrap() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url) {
            renderError(new Error("No active tab found."));
            return;
        }

        if (tab.url.startsWith("https://mail.google.com/")) {
            activeTarget.textContent = "Gmail message";
            await scanCurrentEmail();
            return;
        }

        if (tab.url.startsWith("http://") || tab.url.startsWith("https://")) {
            activeTarget.textContent = tab.url;
            await scanCurrentWebsite();
            return;
        }

        activeTarget.textContent = tab.url;
        renderIdle("Open a website or Gmail message to scan.");
    } catch (error) {
        renderError(error);
    }
}

async function scanCurrentWebsite() {
    setActiveTab("website");
    setLoading("Scanning current website...");

    try {
        await ensureBackendAvailable();
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url) {
            throw new Error("No active website tab found.");
        }
        if (!tab.url.startsWith("http://") && !tab.url.startsWith("https://")) {
            throw new Error("The active tab is not a website.");
        }

        activeTarget.textContent = tab.url;

        const response = await apiFetch(`${API_BASE}/api/scan-url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: tab.url }),
        });

        const data = await parseApiResponse(response);
        renderResult(data, "Website scan");
    } catch (error) {
        renderError(error);
    }
}

async function scanCurrentEmail() {
    setActiveTab("email");
    setLoading("Reading selected Gmail message...");

    try {
        await ensureBackendAvailable();
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url || !tab.url.startsWith("https://mail.google.com/")) {
            throw new Error("Open a Gmail message before running an email scan.");
        }

        activeTarget.textContent = "Gmail message";
        const emailData = await sendTabMessage(tab.id, { action: "getEmail" });
        if (!emailData || (!emailData.body && !emailData.subject && !emailData.sender)) {
            throw new Error("No Gmail message content was found.");
        }

        setLoading("Analyzing email indicators...");
        const response = await apiFetch(`${API_BASE}/api/scan-email`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(emailData),
        });

        const data = await parseApiResponse(response);
        renderResult(data, "Email scan");
    } catch (error) {
        renderError(error);
    }
}

function sendTabMessage(tabId, message) {
    return new Promise((resolve, reject) => {
        chrome.tabs.sendMessage(tabId, message, (response) => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
                return;
            }
            resolve(response);
        });
    });
}

async function ensureBackendAvailable() {
    let response;
    try {
        response = await fetch(`${API_BASE}/`, { method: "GET", cache: "no-store" });
    } catch {
        throw new Error(
            "Scanner backend is not running. Start the Flask app on http://127.0.0.1:5000 and try again."
        );
    }
    if (!response.ok && response.status !== 405) {
        throw new Error("Scanner backend responded with an unexpected error.");
    }
}

async function apiFetch(url, options) {
    try {
        return await fetch(url, options);
    } catch {
        throw new Error(
            "Scanner backend is not running. Start the Flask app on http://127.0.0.1:5000 and try again."
        );
    }
}

async function parseApiResponse(response) {
    let data = {};
    try {
        data = await response.json();
    } catch (error) {
        throw new Error("Scanner returned an unreadable response.");
    }

    if (!response.ok) {
        throw new Error(data.error || `Scanner failed with status ${response.status}.`);
    }

    return data;
}

function renderResult(data, title) {
    const risk = normalizeRisk(data.risk);
    statusPill.textContent = risk;
    statusPill.className = `pill ${risk.toLowerCase()}`;

    resultEl.className = "panel";
    resultEl.replaceChildren();

    const summary = document.createElement("section");
    summary.className = "summary";

    const score = document.createElement("div");
    score.className = `score-ring ${risk.toLowerCase()}`;
    score.textContent = String(data.score ?? 0);

    const summaryText = document.createElement("div");
    const heading = document.createElement("h2");
    heading.textContent = title;
    const description = document.createElement("p");
    description.className = "muted";
    description.textContent = recommendationFor(risk);
    summaryText.append(heading, description);
    summary.append(score, summaryText);

    resultEl.append(summary);
    resultEl.append(buildMetrics(data));
    resultEl.append(buildFindings(data.findings || data.findingMessages || []));
}

function buildMetrics(data) {
    const grid = document.createElement("section");
    grid.className = "grid";

    const domain = data.senderDomain || data.sender_domain || data.registeredDomain || "-";
    const ssl = data.ssl ? (data.ssl.valid ? "Valid" : "Not verified") : "Unavailable";
    const age = data.whois && data.whois.age_days !== undefined ? `${data.whois.age_days} days` : "Unavailable";
    let vt = "Unavailable";
    if (data.virustotal && data.virustotal.malicious !== undefined) {
        const malicious = data.virustotal.malicious ?? 0;
        const suspicious = data.virustotal.suspicious ?? 0;
        vt = `${malicious} malicious, ${suspicious} suspicious`;
    }

    grid.append(
        metric("Domain", domain),
        metric("SSL", ssl),
        metric("Domain age", age),
        metric("VirusTotal", vt)
    );

    if (typeof data.vtScore === "number") {
        grid.append(metric("VT score", String(data.vtScore)));
    }

    if (Array.isArray(data.urlsFound || data.urls_found)) {
        grid.append(metric("URLs found", String((data.urlsFound || data.urls_found).length)));
    }

    return grid;
}

function metric(label, value) {
    const item = document.createElement("div");
    item.className = "metric";
    const labelEl = document.createElement("span");
    labelEl.textContent = label;
    const valueEl = document.createElement("strong");
    valueEl.textContent = value || "-";
    item.append(labelEl, valueEl);
    return item;
}

function buildFindings(findings) {
    const container = document.createElement("section");
    const list = document.createElement("div");
    list.className = "findings";

    if (!findings.length) {
        const empty = document.createElement("p");
        empty.className = "state";
        empty.textContent = "No suspicious indicators found.";
        list.append(empty);
    } else {
        findings.forEach((finding) => list.append(findingCard(finding)));
    }

    container.append(list);
    return container;
}

function findingCard(finding) {
    const normalized = typeof finding === "string"
        ? { message: finding, severity: "Info", evidence: "", scoreImpact: 0 }
        : finding;

    const card = document.createElement("article");
    card.className = "finding";

    const header = document.createElement("div");
    header.className = "finding-header";
    const message = document.createElement("h3");
    message.textContent = normalized.message || "Finding";
    const severity = document.createElement("span");
    severity.className = `severity ${(normalized.severity || "Info").toLowerCase()}`;
    severity.textContent = normalized.severity || "Info";
    header.append(message, severity);

    const evidence = document.createElement("p");
    const impact = normalized.scoreImpact ? `+${normalized.scoreImpact}` : "No score impact";
    evidence.textContent = normalized.evidence ? `${normalized.evidence} | ${impact}` : impact;

    card.append(header, evidence);
    return card;
}

function setLoading(message) {
    statusPill.textContent = "Scanning";
    statusPill.className = "pill neutral";
    resultEl.className = "panel";
    const state = document.createElement("p");
    state.className = "state";
    state.textContent = message;
    resultEl.replaceChildren(state);
}

function renderIdle(message) {
    statusPill.textContent = "Idle";
    statusPill.className = "pill neutral";
    resultEl.className = "panel empty";
    const state = document.createElement("p");
    state.className = "state";
    state.textContent = message;
    resultEl.replaceChildren(state);
}

function renderError(error) {
    statusPill.textContent = "Error";
    statusPill.className = "pill high";
    resultEl.className = "panel";
    const state = document.createElement("p");
    state.className = "state";
    state.textContent = error.message || String(error);
    resultEl.replaceChildren(state);
}

function setActiveTab(mode) {
    scanBtn.classList.toggle("active", mode === "website");
    emailBtn.classList.toggle("active", mode === "email");
}

function normalizeRisk(risk) {
    const value = String(risk || "LOW").toUpperCase();
    return ["LOW", "MEDIUM", "HIGH"].includes(value) ? value : "LOW";
}

function recommendationFor(risk) {
    if (risk === "HIGH") {
        return "Avoid entering credentials or payment data on this page.";
    }
    if (risk === "MEDIUM") {
        return "Proceed carefully and verify the sender or domain.";
    }
    return "No major phishing indicators were detected.";
}

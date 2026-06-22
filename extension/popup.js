console.log("Popup loaded");

document
.getElementById("scanBtn")
.addEventListener(
    "click",
    async () => {

        try {

            console.log("Button clicked");

            let [tab] =
            await chrome.tabs.query({
                active: true,
                currentWindow: true
            });

            console.log("Current URL:", tab.url);

            const response =
            await fetch(
                "http://127.0.0.1:5000/api/scan-url",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                        "application/json"
                    },

                    body: JSON.stringify({
                        url: tab.url
                    })
                }
            );

            console.log(
                "Response:",
                response
            );

            const data =
            await response.json();

            console.log(
                "Data:",
                data
            );

             document
            .getElementById("result")
            .innerHTML = `

            <h3>
            Threat Score:
            ${data.score}/100
            </h3>

            <h3>
            Risk Level:
            ${data.risk}
            </h3>

            <h4>
            VirusTotal
            </h4>

            <p>
            Malicious:
            ${data.virustotal.malicious}
            </p>

            <p>
            Suspicious:
            ${data.virustotal.suspicious}
            </p>

            <h4>
            Domain Information
            </h4>

            <p>
            Domain:
            ${data.whois.domain}
            </p>

            <p>
            Created:
            ${data.whois.creation_date}
            </p>

            <p>
            Age:
            ${data.whois.age_days} days
            </p>

            <h4>
            SSL Certificate
            </h4>

            <p>
            ${
            data.ssl.valid
            ? "Valid"
            : "not verified"
            }
            </p>

            <h4>
            Findings
            </h4>

            ${
            data.findings.length > 0
            ?
            `
            <ul>
            ${data.findings
            .map(f => `<li>${f}</li>`)
            .join("")}
            </ul>
            `
            :
            `
            <p> No suspicious indicators found.</p>
            `
            }

            `;

        }

        catch(error) {

            console.error(
                "FULL ERROR:",
                error
            );

            document
            .getElementById("result")
            .innerHTML =
            error.toString();
        }
    }
);

document
.getElementById("emailBtn")
.addEventListener(
    "click",
    async () => {

        let [tab] =
        await chrome.tabs.query({
            active: true,
            currentWindow: true
        });
        console.log("Sending message to Gmail");

        chrome.tabs.sendMessage(
            tab.id,
            {
                action: "getEmail"
            },

            async (emailData) => {

                console.log("Response:", emailData);

                if (chrome.runtime.lastError) {
                    console.error(
                        chrome.runtime.lastError.message
                    );
                }

                const response =
                await fetch(
                    "http://127.0.0.1:5000/api/scan-email",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                            "application/json"
                        },

                        body: JSON.stringify(
                            emailData
                        )
                    }
                );

                const result =
                await response.json();

                document
.getElementById("result")
.innerHTML = `
<h3>Email Scan</h3>

<p>
<strong>Threat Score:</strong>
${result.score}
</p>

<p>
<strong>Risk Level:</strong>
${result.risk}
</p>

<p>
<strong>Sender Domain:</strong>
${result.sender_domain}
</p>

<p>
<strong>URLs Found:</strong>
${result.urls_found.length}
</p>

<h4>Findings</h4>

${result.findings.join("<br>")}

<h4>URL Analysis</h4>

${
result.url_analysis
.map(url => `
    <div>
        <strong>${url.url}</strong><br>
        Risk: ${url.risk}<br>
        SSL:
        ${url.ssl.valid ? "Valid" : "Invalid"}<br>
        Age:
        ${url.whois.age_days || "Unknown"} days<br>


        VirusTotal Malicious:
        ${url.virustotal.malicious}
    </div>
    <hr>
`)
.join("")
}
`;
            }
        );
    }
);
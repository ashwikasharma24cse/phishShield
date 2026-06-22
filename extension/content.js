console.log("PhishShield content.js loaded");

chrome.runtime.onMessage.addListener(
    (request, sender, sendResponse) => {

        console.log("MESSAGE RECEIVED:", request);

        if (request.action === "getEmail") {
            const data = extractOpenEmail();
            console.log("PhishShield extracted:", {
                sender: data.sender,
                subject: data.subject,
            });
            sendResponse(data);
        }

        return true;
    }
);

// Find the currently expanded message and pull sender/subject/body from it.
// Scoping to the open message is what keeps the sender consistent and avoids
// the logged-in account chip (which lives in the top Google bar, outside
// [role='main']) leaking in as a false "google.com" sender.
function extractOpenEmail() {
    const main =
        document.querySelector("[role='main']") || document.body;

    const message = getOpenMessage(main);

    return {
        sender: extractSender(message, main),
        subject: extractSubject(main),
        body: message.innerText || "",
        html: message.innerHTML || "",
    };
}

function getOpenMessage(main) {
    // Gmail wraps each message in .adn (modern) or .h7 (legacy). In a thread the
    // last message with a rendered body (.a3s) is the expanded one. Falling back
    // to the whole main pane keeps single-message views working.
    const messages = [...main.querySelectorAll(".adn, .h7")];
    for (let i = messages.length - 1; i >= 0; i--) {
        if (messages[i].querySelector(".a3s")) {
            return messages[i];
        }
    }
    return (
        main.querySelector("[role='main'] .adn.ads") ||
        main
    );
}

function extractSender(message, main) {
    // 1. Sender chip inside the open message. The sender is the first [email]
    //    in the header; recipient chips (.g2) come after it. Both message and
    //    main scopes exclude the account chip in the Google bar.
    const scopes = [message, main];
    for (const scope of scopes) {
        if (!scope) continue;

        // Prefer the canonical sender chip (.gD), then any non-recipient [email].
        const senderChip =
            scope.querySelector(".gD[email]") ||
            firstNonRecipientEmail(scope);

        if (senderChip) {
            const email = senderChip.getAttribute("email");
            if (email && email.includes("@")) {
                return email.trim();
            }
        }
    }

    // 2. Last resort: regex an address out of the header text.
    const headerText = (message.innerText || main.innerText || "").slice(0, 2000);
    const match = headerText.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
    return match ? match[0] : "";
}

function firstNonRecipientEmail(scope) {
    // Recipient chips carry class .g2 ("to me", cc, etc.); the sender does not.
    const candidates = [...scope.querySelectorAll("[email]")];
    return candidates.find((el) => !el.classList.contains("g2")) || null;
}

function extractSubject(main) {
    // Subject is the last visible <h2> in the message pane.
    const subjects = [...main.querySelectorAll("h2")]
        .map((x) => x.innerText)
        .filter((x) => x.trim() !== "");
    return subjects.length ? subjects[subjects.length - 1] : "";
}

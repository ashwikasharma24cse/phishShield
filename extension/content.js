console.log("PhishShield content.js loaded");

chrome.runtime.onMessage.addListener(
    (request, sender, sendResponse) => {

        console.log("MESSAGE RECEIVED:", request);

        if (request.action === "getEmail") {

            let subject = "";

            const subjects =
                [...document.querySelectorAll("h2")]
                .map(x => x.innerText)
                .filter(x => x.trim() !== "");

            if (subjects.length > 0) {

                subject =
                subjects[subjects.length - 1];
            }

            let senderEmail = "";

            const emailElement =
                document.querySelector("[email]");

            if (emailElement) {

                senderEmail =
                emailElement.getAttribute(
                    "email"
                );
            }

            const body =
                document.body.innerText;

            console.log({
                sender: senderEmail,
                subject: subject
            });

            sendResponse({
                sender: senderEmail,
                subject: subject,
                body: body
            });
        }

        return true;
    }
);
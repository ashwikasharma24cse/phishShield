import requests

response = requests.post(
    "http://127.0.0.1:5000/api/scan-email",
    json={
        "sender":
        "support@amaz0n-security.com",

        "subject":
        "URGENT: Verify your account",

        "body":
        """
        Click here immediately.

        https://amazonb.com

        Login now.
        """
    }
)

print(
    response.json()
)
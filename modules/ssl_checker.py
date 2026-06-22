import ssl
import socket
from urllib.parse import urlparse


def check_ssl(url):

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            hostname = url

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as ssock:

                cert = ssock.getpeercert()

        return {
            "valid": True,
            "issuer": cert.get("issuer")
        }

    except Exception as e:

       return {
        "valid": False,
        "error": str(e),
        "warning": "SSL could not be verified"
       }
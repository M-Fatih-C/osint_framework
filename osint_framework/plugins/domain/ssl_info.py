import asyncio
import socket
import ssl
from typing import Any, Dict

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule


class SSLInfoModule(BaseModule):
    name = "SSL_Info"
    version = "1.0.0"
    description = "Retrieves TLS certificate metadata from a domain:443 endpoint."
    target_types = ["domain"]
    author = "OSINT_Framework_Team"
    timeout = 15

    def _fetch_cert(self, target: str) -> Dict[str, Any]:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                version = tls_sock.version()

        def _name_to_dict(name_tuples):
            out = {}
            for entry in name_tuples or []:
                for key, value in entry:
                    out[key] = value
            return out

        return {
            "tls_version": version,
            "cipher": cipher[0] if cipher else None,
            "cipher_protocol": cipher[1] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "subject": _name_to_dict(cert.get("subject", [])),
            "issuer": _name_to_dict(cert.get("issuer", [])),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_names": [
                value for key, value in cert.get("subjectAltName", []) if key == "DNS"
            ],
        }

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Fetching TLS certificate for %s", self.name, target)
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._fetch_cert, target),
                timeout=self.timeout,
            )
        except Exception as exc:
            return {"error": str(exc)}


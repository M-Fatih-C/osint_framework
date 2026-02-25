import asyncio
import socket
import ssl
from typing import Any, Dict

from osint_framework.core.logger import logger
from osint_framework.core.provider_models import ProviderResult
from osint_framework.plugins.base import BaseModule


class SocketTlsCertificateProvider:
    name = "socket-tls"

    def fetch(self, timeout: int, target: str) -> ProviderResult:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((target, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
                    version = tls_sock.version()
        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                status="error",
                error=str(exc),
                meta={"reason": "tls_connect_failed"},
            )

        def _name_to_dict(name_tuples):
            out = {}
            for entry in name_tuples or []:
                for key, value in entry:
                    out[key] = value
            return out

        san_values = [value for key, value in cert.get("subjectAltName", []) if key == "DNS"]
        return ProviderResult(
            provider=self.name,
            status="ok",
            payload={
                "tls_version": version,
                "cipher": cipher[0] if cipher else None,
                "cipher_protocol": cipher[1] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "subject": _name_to_dict(cert.get("subject", [])),
                "issuer": _name_to_dict(cert.get("issuer", [])),
                "serial_number": cert.get("serialNumber"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "subject_alt_names": san_values,
            },
            meta={"san_count": len(san_values)},
        )


class SSLInfoModule(BaseModule):
    name = "SSL_Info"
    version = "1.1.0"
    description = "Retrieves TLS certificate metadata using provider abstraction (socket TLS backend)."
    target_types = ["domain"]
    author = "OSINT_Framework_Team"
    timeout = 15

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Fetching TLS certificate for %s", self.name, target)
        provider = SocketTlsCertificateProvider()
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(provider.fetch, self.timeout, target),
                timeout=self.timeout,
            )
            return result.to_module_output() if isinstance(result, ProviderResult) else {
                "provider": provider.name,
                "status": "error",
                "error": "Invalid provider result",
            }
        except Exception as exc:
            return {
                "provider": provider.name,
                "status": "error",
                "error": str(exc),
                "provider_meta": {"reason": "timeout_or_runtime"},
            }

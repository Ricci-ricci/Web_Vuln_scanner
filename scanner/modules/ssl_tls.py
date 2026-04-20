from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from scanner.modules.base import BaseModule, Form
from scanner.report.models import Finding, Severity
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)


class SSLTLSModule(BaseModule):
    name = "ssl_tls"
    description = "Audits SSL/TLS certificate validity, expiry, and protocol version."

    def run(self, urls: list[str], forms: list[Form]) -> list[Finding]:
        findings: list[Finding] = []
        if not urls:
            return findings

        first = urlparse(urls[0])

        if first.scheme != "https":
            findings.append(
                Finding(
                    module=self.name,
                    title="Target Not Using HTTPS",
                    severity=Severity.HIGH,
                    url=urls[0],
                    description="The target is served over HTTP. All traffic is transmitted in plaintext.",
                    evidence=f"Target URL scheme is '{first.scheme}'",
                    remediation="Obtain a TLS certificate and redirect all HTTP traffic to HTTPS.",
                )
            )
            return findings

        hostname = first.hostname or ""
        port = first.port or 443
        findings.extend(self._check_certificate(hostname, port, urls[0]))
        return findings

    def _check_certificate(self, hostname: str, port: int, url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                    cert = tls.getpeercert()
                    protocol = tls.version()

            not_after = str(cert.get("notAfter", "") if cert else "")
            if not_after:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days

                if days_left < 0:
                    findings.append(
                        Finding(
                            module=self.name,
                            title="SSL Certificate Expired",
                            severity=Severity.CRITICAL,
                            url=url,
                            description=f"The SSL certificate expired {abs(days_left)} day(s) ago.",
                            evidence=f"Certificate notAfter: {not_after}",
                            remediation="Renew the SSL certificate immediately.",
                        )
                    )
                elif days_left < 30:
                    findings.append(
                        Finding(
                            module=self.name,
                            title="SSL Certificate Expiring Soon",
                            severity=Severity.MEDIUM,
                            url=url,
                            description=f"The SSL certificate expires in {days_left} day(s).",
                            evidence=f"Certificate notAfter: {not_after}",
                            remediation="Renew the SSL certificate before it expires.",
                        )
                    )

            if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                findings.append(
                    Finding(
                        module=self.name,
                        title="Weak TLS Protocol Version",
                        severity=Severity.HIGH,
                        url=url,
                        description=f"The server negotiated {protocol}, which is considered insecure.",
                        evidence=f"Negotiated protocol: {protocol}",
                        remediation="Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and TLS 1.3.",
                    )
                )

        except ssl.SSLCertVerificationError as e:
            findings.append(
                Finding(
                    module=self.name,
                    title="SSL Certificate Validation Failed",
                    severity=Severity.CRITICAL,
                    url=url,
                    description="The server's SSL certificate could not be verified.",
                    evidence=str(e),
                    remediation="Ensure the certificate is signed by a trusted CA and the hostname matches.",
                )
            )
        except Exception as e:
            logger.warning(
                f"[ssl_tls] Could not inspect certificate for {hostname}: {e}"
            )

        logger.info(f"[ssl_tls] {len(findings)} finding(s)")
        return findings

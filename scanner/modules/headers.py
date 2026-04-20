from __future__ import annotations

from scanner.modules.base import BaseModule, Form
from scanner.report.models import Finding, Severity
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)

SECURITY_HEADERS: list[tuple[str, Severity, str, str, str]] = [
    (
        "Content-Security-Policy",
        Severity.HIGH,
        "Missing Content-Security-Policy Header",
        "Content-Security-Policy is not set. This allows attackers to inject malicious scripts (XSS).",
        "Add a Content-Security-Policy header with a strict policy.",
    ),
    (
        "X-Frame-Options",
        Severity.MEDIUM,
        "Missing X-Frame-Options Header",
        "X-Frame-Options is not set. The page may be embedded in an iframe, enabling clickjacking attacks.",
        "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
    ),
    (
        "X-Content-Type-Options",
        Severity.LOW,
        "Missing X-Content-Type-Options Header",
        "X-Content-Type-Options is not set. Browsers may MIME-sniff the content type.",
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    (
        "Strict-Transport-Security",
        Severity.HIGH,
        "Missing Strict-Transport-Security Header",
        "HSTS is not set. Connections may be downgraded from HTTPS to HTTP by an attacker.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "Missing Referrer-Policy Header",
        "Referrer-Policy is not set. Sensitive URL data may leak via the Referer header.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
    (
        "Permissions-Policy",
        Severity.LOW,
        "Missing Permissions-Policy Header",
        "Permissions-Policy is not set. Browser features are not explicitly restricted.",
        "Add a Permissions-Policy header to restrict access to browser APIs.",
    ),
]


class HeadersModule(BaseModule):
    name = "headers"
    description = "Checks for missing HTTP security response headers."

    def run(self, urls: list[str], forms: list[Form]) -> list[Finding]:
        findings: list[Finding] = []
        checked: set[str] = set()

        for url in urls:
            if url in checked:
                continue
            checked.add(url)

            response = self.client.get(url)
            if response is None:
                continue

            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            is_https = url.startswith("https")

            for header, severity, title, description, remediation in SECURITY_HEADERS:
                if header == "Strict-Transport-Security" and not is_https:
                    continue
                if header.lower() not in headers_lower:
                    findings.append(
                        Finding(
                            module=self.name,
                            title=title,
                            severity=severity,
                            url=url,
                            description=description,
                            evidence=f"Header '{header}' was absent in the response.",
                            remediation=remediation,
                        )
                    )
                    logger.debug(f"[headers] Missing '{header}' on {url}")

        logger.info(f"[headers] {len(findings)} finding(s)")
        return findings

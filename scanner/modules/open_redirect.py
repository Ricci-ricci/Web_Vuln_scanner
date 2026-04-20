from __future__ import annotations

from urllib.parse import urlparse

from scanner.modules.base import BaseModule, Form
from scanner.report.models import Finding, Severity
from scanner.utils.helpers import extract_parameter, inject_parameter
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)

REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "next", "return", "return_url",
    "goto", "dest", "destination", "target", "redir", "r", "u",
    "link", "forward",
}

REDIRECT_PAYLOAD = "https://evil.example.com"


class OpenRedirectModule(BaseModule):
    name = "open_redirect"
    description = "Tests for open redirect vulnerabilities in URL parameters."

    def run(self, urls: list[str], forms: list[Form]) -> list[Finding]:
        findings: list[Finding] = []
        for url in urls:
            params = extract_parameter(url)
            if not params:
                continue
            for param in params:
                if param.lower() not in REDIRECT_PARAMS:
                    continue
                test_url = inject_parameter(url, param, REDIRECT_PAYLOAD)
                response = self.client.get(test_url, follow_redirects=False)
                if response is None:
                    continue
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "")
                    if urlparse(location).hostname == urlparse(REDIRECT_PAYLOAD).hostname:
                        findings.append(
                            Finding(
                                module=self.name,
                                title="Open Redirect",
                                severity=Severity.MEDIUM,
                                url=url,
                                description=f"Parameter '{param}' redirects to an arbitrary external URL without validation.",
                                evidence=f"Request to {test_url} redirected to {location}",
                                remediation="Validate redirect targets against an allowlist of trusted URLs.",
                            )
                        )
                        logger.debug(f"[open_redirect] Found on {url} param='{param}'")
        logger.info(f"[open_redirect] {len(findings)} finding(s)")
        return findings

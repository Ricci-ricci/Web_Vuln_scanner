from __future__ import annotations

from scanner.modules.base import BaseModule, Form
from scanner.report.models import Finding, Severity
from scanner.utils.helpers import extract_parameter, inject_parameter
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>",
]


class XSSModule(BaseModule):
    name = "xss"
    description = (
        "Tests for reflected Cross-Site Scripting in URL parameters and forms."
    )

    def run(self, urls: list[str], forms: list[Form]) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._test_urls(urls))
        findings.extend(self._test_forms(forms))
        logger.info(f"[xss] {len(findings)} finding(s)")
        return findings

    def _test_urls(self, urls: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for url in urls:
            params = extract_parameter(url)
            if not params:
                continue
            for param in params:
                for payload in XSS_PAYLOADS:
                    test_url = inject_parameter(url, param, payload)
                    response = self.client.get(test_url, follow_redirects=True)
                    if response and payload in response.text:
                        findings.append(
                            Finding(
                                module=self.name,
                                title="Reflected XSS",
                                severity=Severity.HIGH,
                                url=url,
                                description=f"Parameter '{param}' reflects unsanitised input in the response.",
                                evidence=f"Payload reflected: {payload} â tested at {test_url}",
                                remediation="Encode all user-supplied output. Implement a strict Content-Security-Policy.",
                            )
                        )
                        logger.debug(f"[xss] Found on {url} param='{param}'")
                        break
        return findings

    def _test_forms(self, forms: list[Form]) -> list[Finding]:
        findings: list[Finding] = []
        for form in forms:
            for payload in XSS_PAYLOADS:
                data = {k: payload for k in form.fields}
                if form.method == "POST":
                    response = self.client.post(
                        form.action, data=data, follow_redirects=True
                    )
                else:
                    response = self.client.get(
                        form.action, params=data, follow_redirects=True
                    )
                if response and payload in response.text:
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Reflected XSS via Form",
                            severity=Severity.HIGH,
                            url=form.action,
                            description="A form field reflects unsanitised input in the response.",
                            evidence=f"Payload reflected: {payload} â {form.method} form at {form.action}",
                            remediation="Encode all user-supplied output. Implement a strict Content-Security-Policy.",
                        )
                    )
                    logger.debug(f"[xss] Found on form {form.action}")
                    break
        return findings

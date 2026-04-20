from __future__ import annotations

import re

from scanner.modules.base import BaseModule, Form
from scanner.report.models import Finding, Severity
from scanner.utils.helpers import extract_parameter, inject_parameter
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR 1=1--',
    "';--",
    "1; DROP TABLE users--",
]

SQLI_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d+|pg_query|sqlite3|syntax error|"
    r"unclosed quotation|microsoft ole db|odbc driver|"
    r"warning.*mysql|division by zero|"
    r"supplied argument is not a valid|invalid query)",
    re.IGNORECASE,
)


class SQLiModule(BaseModule):
    name = "sqli"
    description = "Tests for error-based SQL injection in URL parameters and forms."

    def run(self, urls: list[str], forms: list[Form]) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._test_urls(urls))
        findings.extend(self._test_forms(forms))
        logger.info(f"[sqli] {len(findings)} finding(s)")
        return findings

    def _test_urls(self, urls: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for url in urls:
            params = extract_parameter(url)
            if not params:
                continue
            for param in params:
                for payload in SQLI_PAYLOADS:
                    test_url = inject_parameter(url, param, payload)
                    response = self.client.get(test_url, follow_redirects=True)
                    if response and SQLI_ERROR_PATTERNS.search(response.text):
                        findings.append(
                            Finding(
                                module=self.name,
                                title="Potential SQL Injection",
                                severity=Severity.CRITICAL,
                                url=url,
                                description=f"Parameter \x27{param}\x27 triggered a database error in the response.",
                                evidence=f"Payload: {payload!r} \xe2\x80\x94 tested at {test_url}",
                                remediation="Use parameterised queries or prepared statements. Never interpolate user input into SQL.",
                            )
                        )
                        logger.debug(f"[sqli] Found on {url} param=\x27{param}\x27")
                        break
        return findings

    def _test_forms(self, forms: list[Form]) -> list[Finding]:
        findings: list[Finding] = []
        for form in forms:
            for payload in SQLI_PAYLOADS:
                data = {k: payload for k in form.fields}
                if form.method == "POST":
                    response = self.client.post(
                        form.action, data=data, follow_redirects=True
                    )
                else:
                    response = self.client.get(
                        form.action, params=data, follow_redirects=True
                    )
                if response and SQLI_ERROR_PATTERNS.search(response.text):
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Potential SQL Injection via Form",
                            severity=Severity.CRITICAL,
                            url=form.action,
                            description="A form field triggered a database error in the response.",
                            evidence=f"Payload: {payload!r} \xe2\x80\x94 {form.method} form at {form.action}",
                            remediation="Use parameterised queries or prepared statements.",
                        )
                    )
                    logger.debug(f"[sqli] Found on form {form.action}")
                    break
        return findings

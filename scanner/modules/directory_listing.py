from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from scanner.modules.base import BaseModule, Form
from scanner.report.models import Finding, Severity
from scanner.utils.helpers import join_url
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)

COMMON_DIRS = [
    "/admin/", "/backup/", "/uploads/", "/files/",
    "/static/", "/assets/", "/images/", "/logs/",
    "/tmp/", "/config/", "/data/", "/db/",
    "/includes/", "/src/", "/",
]

LISTING_PATTERNS = [
    "index of /",
    "directory listing",
    "parent directory",
    "<title>index of",
]


class DirectoryListingModule(BaseModule):
    name = "directory_listing"
    description = "Checks common paths for exposed directory listings."

    def run(self, urls: list[str], forms: list[Form]) -> list[Finding]:
        findings: list[Finding] = []
        base_urls: set[str] = set()

        for url in urls:
            p = urlparse(url)
            base = urlunparse((p.scheme, p.netloc, "", "", "", ""))
            base_urls.add(base)

        for base in base_urls:
            for path in COMMON_DIRS:
                target_url = join_url(base, path)
                response = self.client.get(target_url, follow_redirects=True)
                if response is None:
                    continue
                if response.status_code == 200:
                    body_lower = response.text.lower()
                    if any(pattern in body_lower for pattern in LISTING_PATTERNS):
                        findings.append(
                            Finding(
                                module=self.name,
                                title="Directory Listing Enabled",
                                severity=Severity.MEDIUM,
                                url=target_url,
                                description="The server exposes a directory listing, revealing its file structure to attackers.",
                                evidence=f"Directory listing detected at {target_url}",
                                remediation="Disable directory listing in your web server configuration (e.g. 'Options -Indexes' in Apache).",
                            )
                        )
                        logger.debug(f"[directory_listing] Found at {target_url}")

        logger.info(f"[directory_listing] {len(findings)} finding(s)")
        return findings

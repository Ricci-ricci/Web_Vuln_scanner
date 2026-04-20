from __future__ import annotations

from datetime import datetime, timezone
from typing import Type

from scanner.core.http_client import HttpClient
from scanner.core.target import Target
from scanner.crawler.spider import Spider
from scanner.modules.base import BaseModule
from scanner.modules.directory_listing import DirectoryListingModule
from scanner.modules.headers import HeadersModule
from scanner.modules.open_redirect import OpenRedirectModule
from scanner.modules.sqli import SQLiModule
from scanner.modules.ssl_tls import SSLTLSModule
from scanner.modules.xss import XSSModule
from scanner.report.models import ScanReport
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)

ALL_MODULES: list[Type[BaseModule]] = [
    HeadersModule,
    XSSModule,
    SQLiModule,
    OpenRedirectModule,
    DirectoryListingModule,
    SSLTLSModule,
]

MODULE_MAP: dict[str, Type[BaseModule]] = {m.name: m for m in ALL_MODULES}


class Engine:
    def __init__(
        self,
        target: Target,
        modules: list[str] | None = None,
        max_depth: int = 3,
        max_pages: int = 200,
        timeout: int = 10,
    ) -> None:
        self.target = target
        self.module_names = modules or list(MODULE_MAP.keys())
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout

    def run(self) -> ScanReport:
        report = ScanReport(
            target_url=self.target.url,
            started_at=datetime.now(timezone.utc),
        )

        with HttpClient(self.target, timeout=self.timeout) as client:
            logger.info("Starting spider...")
            spider = Spider(
                self.target,
                client,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
            )
            urls, forms = spider.crawl()
            logger.info(f"Spider finished â {len(urls)} URL(s), {len(forms)} form(s)")

            for name in self.module_names:
                module_cls = MODULE_MAP.get(name)
                if module_cls is None:
                    logger.warning(f"Unknown module: {name!r}, skipping.")
                    continue
                logger.info(f"Running module: {name}")
                module = module_cls(client)
                findings = module.run(urls, forms)
                report.findings.extend(findings)
                logger.info(f"Module '{name}' found {len(findings)} issue(s)")

        report.finished_at = datetime.now(timezone.utc)
        return report

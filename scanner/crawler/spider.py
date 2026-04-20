from __future__ import annotations

from collections import deque
from urllib.parse import urldefrag

from bs4 import BeautifulSoup

from scanner.core.http_client import HttpClient
from scanner.core.target import Target
from scanner.modules.base import Form
from scanner.utils.helpers import join_url, url_binary
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)


class Spider:
    """BFS web crawler that discovers URLs and HTML forms within a target scope."""

    def __init__(
        self,
        target: Target,
        client: HttpClient,
        max_depth: int = 3,
        max_pages: int = 200,
    ) -> None:
        self.target = target
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages

    def crawl(self) -> tuple[list[str], list[Form]]:
        """Crawl the target and return (urls, forms)."""
        visited: set[str] = set()
        urls: list[str] = []
        forms: list[Form] = []

        queue: deque[tuple[str, int]] = deque()
        seed = self._clean(self.target.url)
        queue.append((seed, 0))
        visited.add(seed)

        logger.info(
            f"Spider starting from {seed} "
            f"(max_depth={self.max_depth}, max_pages={self.max_pages})"
        )

        while queue:
            if len(urls) >= self.max_pages:
                logger.info(f"Reached max_pages limit ({self.max_pages}), stopping.")
                break

            url, depth = queue.popleft()

            if url_binary(url):
                continue

            response = self.client.get(url)
            if response is None:
                continue

            urls.append(url)
            logger.debug(f"[{len(urls)}/{self.max_pages}] Crawled {url} (depth={depth})")

            if depth >= self.max_depth:
                continue

            try:
                soup = BeautifulSoup(response.text, "html.parser")
            except Exception as exc:
                logger.warning(f"Failed to parse HTML at {url}: {exc}")
                continue

            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                absolute = self._clean(join_url(url, href))
                if (
                    absolute not in visited
                    and self.target.in_scope(absolute)
                    and not url_binary(absolute)
                ):
                    visited.add(absolute)
                    queue.append((absolute, depth + 1))

            for tag in soup.find_all("form"):
                form = self._parse_form(url, tag)
                if form is not None:
                    forms.append(form)

        logger.info(
            f"Crawl complete â {len(urls)} URLs, {len(forms)} forms discovered."
        )
        return urls, forms

    @staticmethod
    def _clean(url: str) -> str:
        clean, _ = urldefrag(url)
        return clean

    @staticmethod
    def _parse_form(page_url: str, tag: object) -> Form | None:
        try:
            from bs4 import Tag
            if not isinstance(tag, Tag):
                return None
            action = tag.get("action") or page_url
            action = join_url(page_url, str(action))
            method = str(tag.get("method") or "get").strip()

            fields: dict[str, str] = {}
            for inp in tag.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if not name:
                    continue
                value = inp.get("value") or ""
                fields[str(name)] = str(value)

            if not fields:
                return None

            return Form(action=action, method=method, fields=fields)
        except Exception as exc:
            logger.warning(f"Could not parse form on {page_url}: {exc}")
            return None

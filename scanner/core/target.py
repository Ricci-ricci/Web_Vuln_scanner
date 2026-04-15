from dataclasses import dataclass, field

from scanner.utils.helpers import (
    extract_base_url,
    extract_domain,
    is_valid_url,
    normalize_url,
)
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)


@dataclass
class Target:
    raw_url: str
    url: str = field(init=False)
    base_url: str = field(init=False)
    domain: str = field(init=False)
    scheme: str = field(init=False)
    is_https: bool = field(init=False)

    def __post_init__(self):
        if not is_valid_url(self.raw_url):
            raise ValueError(f"Invalid or unsupported Url : {self.raw_url}")
        self.url = normalize_url(self.raw_url)
        self.base_url = extract_base_url(self.url)
        self.domain = extract_domain(self.url)
        self.scheme = self.url.split("://")[0]
        self.is_https = self.scheme == "https"

        logger.info(f"Target initialised - {self.url}")

    def in_scope(self, url: str) -> bool:
        from scanner.utils.helpers import is_same_host

        return is_same_host(url, self.url)

    def __str__(self) -> str:
        return self.url

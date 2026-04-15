import httpx

from scanner.core.target import Target
from scanner.utils.loggers import get_logger

logger = get_logger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

DEFAULT_TIMEOUT = 10


class HttpClient:
    def __init__(
        self,
        target: Target,
        timeout: int = DEFAULT_TIMEOUT,
        follow_redirects: bool = True,
        extra_headers: dict | None = None,
    ):
        self.target = target
        self.timeout = timeout
        self.follow_redirects = follow_redirects

        headers = {**DEFAULT_HEADERS, **(extra_headers or {})}
        self.client = httpx.Client(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
        )

        logger.debug(f"HttpClient ready for {target.domain}")
    def get(self , url:str , follow_redirects : bool | None = None , **kwargs) -> httpx.Response | None :
        try:
            redirects = follow_redirects if follow_redirects is not None
            response = self.client.get(url , follow_redirects=redirects , **kwargs)
            logger.debug(f"Get {url} -> {response.status_code}")
            return response

        except httpx.TimeoutException:
            logger.warning(f"Timeout on Get {url}")
            return None

        except httpx.RequestError as e:
            logger.warning(f"Request Error on Get {url} - {e}")
            return None

    def post(self , url:str , data:dict , follow_redirects : bool | None = None , **kwargs ) -> httpx.Response | None:
        try :
            redirects = follow_redirects if follow_redirects is not None else self.follow_redirects
            response = self.client.post(url , data = data , follow_redirects=redirects , **kwargs
            )
            logger.debug(f"Post {url} -> {response.status_code}")
            return response
        except httpx.TimeoutException:
            logger.warning(f"Timeout on Post {url}")
            return None
        except httpx.RequestError as e:
            logger.warning(f"Request error on Post {url} - {e}")
            return None
    def close(self):
        self.client.close
        logger.debug("HttpClient Session closed")

    def __enter__(self):
        return self

    def __exit__(self):
        return self.close()

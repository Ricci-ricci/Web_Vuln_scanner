from urllib.parse import (
    parse_qs,
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".bmp",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".7z",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
    ".mkv",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".exe",
    ".dll",
    ".bin",
}

VALID_SCHEMES = {"http", "https"}


def normalize_url(url: str) -> str:
    parse = urlparse(url.strip().lower())
    netloc = parse.netloc
    if parse.port == 80 and parse.scheme == "http":
        netloc = parse.hostname
    elif parse.port == 443 and parse.scheme == "https":
        netloc = parse.hostname
    path = parse.path.strip("/") or "/"
    url = urlunparse((parse.scheme, netloc, path, "", parse.query, ""))
    return url


def is_same_host(url: str, target_url: str) -> bool:
    value = urlparse(url).hostname == urlparse(target_url).hostname
    return value


def join_url(base: str, url: str) -> str:
    return urljoin(base, url)


def extract_domain(url: str) -> str:
    return urlparse(url).hostname or ""


def extract_base_url(url: str) -> str:
    parse = urlparse(url)
    return urlunparse((parse.scheme, parse.netloc, "", "", "", ""))


def extract_parameter(url: str) -> dict[str, str]:
    parse = urlparse(url)
    parse_qls = parse_qsl(parse.query)
    return dict(parse_qls)


def inject_parameter(url: str, params_name: str, payload: str) -> str:
    parse = urlparse(url)
    params = dict(parse_qsl(parse.query))
    params[params_name] = payload
    new_query = urlencode(params)
    return urlunparse(
        (parse.scheme, parse.netloc, parse.path, parse.params, new_query, "")
    )


def is_valid_url(url: str) -> bool:
    try:
        parse = urlparse(url)
        return parse.scheme in VALID_SCHEMES and bool(parse.netloc)
    except Exception:
        return False


def url_binary(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in BINARY_EXTENSIONS)

"""
crawler.py — Deep Crawling Engine for AegisHealth Scanner.

Performs BFS-based crawling of a target site to discover:
  • Internal page URLs
  • API endpoints (REST / GraphQL patterns)
  • HTML forms and their input fields
  • Query parameters used across the site

The discovered surface is then fed into the existing check modules so
every scan covers far more than just the landing page.

Usage:
    from scanner.crawler import crawl_target
    result = crawl_target("https://example.com", max_depth=2)
"""

import re
import logging
from collections import deque
from urllib.parse import (
    urlparse, urljoin, parse_qs, urldefrag, urlunparse,
)
from typing import Dict, List, Set, Any

import requests
from bs4 import BeautifulSoup

# ── Configuration ────────────────────────────────────────────────────────────
REQUEST_TIMEOUT = 5          # seconds per HTTP request
MAX_URLS = 100               # hard cap to prevent runaway crawls
CRAWL_DELAY = 0.0            # seconds between requests (0 = no delay)

# Patterns that mark a URL as an API endpoint
API_PATTERNS = re.compile(
    r"/api/|/v[0-9]+/|/graphql|\.json$|/rest/|/rpc/",
    re.IGNORECASE,
)

# Fetch/XHR patterns inside <script> blocks or .js files
JS_API_PATTERN = re.compile(
    r"""(?:fetch|axios|XMLHttpRequest|\$\.ajax|\$\.get|\$\.post|http\.get|http\.post)"""
    r"""\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

# File extensions we never want to crawl (binary / static assets)
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov", ".webm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
}

logger = logging.getLogger("aegis.crawler")


# ─────────────────────────────────────────────────────────────────────────────
#  URL helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_url(url: str) -> str:
    """Strip fragment, trailing slash, and lowercase the scheme+host."""
    url, _ = urldefrag(url)
    parsed = urlparse(url)
    # Lowercase scheme + host; keep path case-sensitive
    normalised = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path.rstrip("/") or "/",
        parsed.params,
        parsed.query,
        "",  # no fragment
    ))
    return normalised


def _is_same_domain(url: str, base_domain: str) -> bool:
    """Return True if *url* belongs to the same domain as *base_domain*."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    return host == base_domain or host.endswith(f".{base_domain}")


def _should_skip(url: str) -> bool:
    """Return True for URLs pointing to binary/static assets."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def _is_api_url(url: str) -> bool:
    """Return True if the URL looks like an API endpoint."""
    return bool(API_PATTERNS.search(url))


def _extract_query_params(url: str) -> List[str]:
    """Pull unique query-parameter names from a URL."""
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())


# ─────────────────────────────────────────────────────────────────────────────
#  Page fetching
# ─────────────────────────────────────────────────────────────────────────────

def _fetch(url: str) -> requests.Response | None:
    """GET a URL safely, returning the Response or None."""
    try:
        return requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "AegisHealth-Scanner/1.0"},
        )
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  Extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_links(soup: BeautifulSoup, page_url: str) -> List[str]:
    """Extract all <a href=""> links and resolve them to absolute URLs."""
    links: List[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:")):
            continue
        absolute = urljoin(page_url, href)
        links.append(_normalise_url(absolute))
    return links


def _extract_forms(soup: BeautifulSoup, page_url: str) -> List[Dict[str, Any]]:
    """
    Extract <form> elements with their attributes and child inputs.

    Returns a list of dicts:
        {
            "action": str,          # resolved absolute URL
            "method": "GET"|"POST",
            "inputs": [
                {"name": str, "type": str}, ...
            ]
        }
    """
    forms: List[Dict[str, Any]] = []
    for form_tag in soup.find_all("form"):
        action_raw = form_tag.get("action", "").strip() or page_url
        action = urljoin(page_url, action_raw)
        method = (form_tag.get("method") or "GET").upper()

        inputs: List[Dict[str, str]] = []
        for inp in form_tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            input_type = inp.get("type", "text")
            if name:
                inputs.append({"name": name, "type": input_type})

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })
    return forms


def _extract_js_api_calls(soup: BeautifulSoup, page_url: str) -> List[str]:
    """Scan inline <script> blocks for fetch/axios/XHR URL patterns."""
    api_urls: List[str] = []
    for script in soup.find_all("script"):
        text = script.string or ""
        for match in JS_API_PATTERN.finditer(text):
            raw_url = match.group(1)
            if raw_url.startswith(("http://", "https://", "/")):
                absolute = urljoin(page_url, raw_url)
                api_urls.append(_normalise_url(absolute))
    return api_urls


def _extract_linked_js_apis(
    soup: BeautifulSoup,
    page_url: str,
    base_domain: str,
) -> List[str]:
    """
    Download same-domain .js files referenced via <script src="...">
    and scan them for API call patterns.
    """
    api_urls: List[str] = []
    for script in soup.find_all("script", src=True):
        src = script["src"]
        js_url = urljoin(page_url, src)
        # Only fetch same-domain JS to avoid scanning third-party libs
        if not _is_same_domain(js_url, base_domain):
            continue
        resp = _fetch(js_url)
        if resp is None or resp.status_code != 200:
            continue
        for match in JS_API_PATTERN.finditer(resp.text):
            raw_url = match.group(1)
            if raw_url.startswith(("http://", "https://", "/")):
                absolute = urljoin(page_url, raw_url)
                api_urls.append(_normalise_url(absolute))
    return api_urls


# ─────────────────────────────────────────────────────────────────────────────
#  Advanced discovery: JS files, assets, hidden links, robots.txt, sitemap
# ─────────────────────────────────────────────────────────────────────────────

# Matches absolute/relative URLs hidden inside HTML comments.
_HTML_COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
_COMMENT_URL_PATTERN = re.compile(r"""(?:href|src|url)\s*=?\s*['"]?([/\w][^\s'"<>]+)""", re.IGNORECASE)

_ASSET_TAGS = {
    "img": "src",
    "link": "href",
    "source": "src",
    "video": "src",
    "audio": "src",
}


def _extract_js_files(soup: BeautifulSoup, page_url: str) -> List[str]:
    """Return absolute URLs of all referenced JavaScript files."""
    js_files: List[str] = []
    for script in soup.find_all("script", src=True):
        js_files.append(_normalise_url(urljoin(page_url, script["src"])))
    return js_files


def _extract_assets(soup: BeautifulSoup, page_url: str) -> List[str]:
    """Return absolute URLs of static assets (images, css, media)."""
    assets: List[str] = []
    for tag_name, attr in _ASSET_TAGS.items():
        for tag in soup.find_all(tag_name):
            val = tag.get(attr)
            if val:
                assets.append(_normalise_url(urljoin(page_url, val)))
    return assets


def _extract_hidden_links(html: str, page_url: str) -> List[str]:
    """Extract links buried inside HTML comments (often forgotten endpoints)."""
    hidden: List[str] = []
    for comment in _HTML_COMMENT_PATTERN.findall(html):
        for match in _COMMENT_URL_PATTERN.findall(comment):
            if match.startswith(("http://", "https://", "/")):
                hidden.append(_normalise_url(urljoin(page_url, match)))
    return hidden


def _discover_robots(base_url: str) -> Dict[str, Any]:
    """
    Fetch and parse robots.txt.

    Returns ``{"present": bool, "disallow": [...], "sitemaps": [...]}``.
    Disallowed paths frequently reveal sensitive/hidden areas worth scanning.
    """
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    result: Dict[str, Any] = {"present": False, "disallow": [], "sitemaps": []}
    resp = _fetch(robots_url)
    if resp is None or resp.status_code != 200 or "html" in resp.headers.get("Content-Type", "").lower():
        return result
    result["present"] = True
    for line in resp.text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                result["disallow"].append(urljoin(robots_url, path))
        elif line.lower().startswith("sitemap:"):
            result["sitemaps"].append(line.split(":", 1)[1].strip())
    return result


def _discover_sitemap(base_url: str, extra_sitemaps: List[str]) -> List[str]:
    """Fetch sitemap.xml (and any robots-declared sitemaps) and extract <loc> URLs."""
    parsed = urlparse(base_url)
    candidates = list(dict.fromkeys(
        extra_sitemaps + [f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"]
    ))
    found: List[str] = []
    for sitemap_url in candidates[:5]:
        resp = _fetch(sitemap_url)
        if resp is None or resp.status_code != 200:
            continue
        for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", resp.text, re.IGNORECASE):
            found.append(_normalise_url(loc))
    return found


# ─────────────────────────────────────────────────────────────────────────────
#  Optional: Playwright-based JS rendering
# ─────────────────────────────────────────────────────────────────────────────

def _try_playwright_fetch(url: str) -> str | None:
    """
    Attempt to render the page with Playwright (headless Chromium).
    Returns the fully-rendered HTML string, or None if Playwright is
    not installed.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return None

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=15_000)
            html = page.content()
            browser.close()
            return html
    except Exception as exc:
        logger.debug("Playwright rendering failed for %s: %s", url, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  Main crawl function
# ─────────────────────────────────────────────────────────────────────────────

def crawl_target(base_url: str, max_depth: int = 2) -> Dict[str, Any]:
    """
    BFS-crawl *base_url* up to *max_depth* levels deep.

    Parameters
    ----------
    base_url  : Root URL to start crawling from.
    max_depth : Maximum link-depth from the root (0 = root only).

    Returns
    -------
    {
        "urls":           list[str]  — all discovered internal page URLs,
        "api_endpoints":  list[str]  — URLs that look like API endpoints,
        "forms":          list[dict] — extracted <form> elements,
        "query_params":   list[str]  — unique query-parameter names,
    }
    """
    base_url = _normalise_url(base_url)
    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc.lower()

    # BFS state
    visited: Set[str] = set()
    queue: deque = deque()
    queue.append((base_url, 0))  # (url, depth)

    # Result accumulators
    all_urls: List[str] = []
    api_endpoints: Set[str] = set()
    all_forms: List[Dict[str, Any]] = []
    query_params: Set[str] = set()
    js_files: Set[str] = set()
    assets: Set[str] = set()
    hidden_links: Set[str] = set()

    # ── Pre-crawl: robots.txt + sitemap discovery (seeds the BFS queue) ──────
    robots = _discover_robots(base_url)
    sitemap_urls = _discover_sitemap(base_url, robots.get("sitemaps", []))

    # Seed the queue with same-domain sitemap + robots-disallowed URLs so the
    # crawler also visits pages that aren't linked from the landing page.
    for seed in list(sitemap_urls) + list(robots.get("disallow", [])):
        if _is_same_domain(seed, base_domain) and not _should_skip(seed):
            queue.append((seed, 1))
        # Disallowed paths are inherently "hidden" surface worth recording.
    for dis in robots.get("disallow", []):
        hidden_links.add(dis)

    while queue and len(visited) < MAX_URLS:
        current_url, depth = queue.popleft()

        if current_url in visited:
            continue
        if _should_skip(current_url):
            continue

        visited.add(current_url)
        logger.debug("Crawling [depth=%d]: %s", depth, current_url)

        # ── Fetch the page ───────────────────────────────────────────────
        # Try Playwright first for JS-rendered content; fall back to requests
        html = _try_playwright_fetch(current_url)
        if html is not None:
            soup = BeautifulSoup(html, "html.parser")
            all_urls.append(current_url)
        else:
            resp = _fetch(current_url)
            if resp is None or resp.status_code >= 400:
                continue
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                # Not an HTML page — record it (could be an API) but don't parse
                all_urls.append(current_url)
                if _is_api_url(current_url):
                    api_endpoints.add(current_url)
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            all_urls.append(current_url)

        # ── Classify current URL ─────────────────────────────────────────
        if _is_api_url(current_url):
            api_endpoints.add(current_url)

        # ── Extract query params ─────────────────────────────────────────
        for param in _extract_query_params(current_url):
            query_params.add(param)

        # ── Extract forms ────────────────────────────────────────────────
        page_forms = _extract_forms(soup, current_url)
        all_forms.extend(page_forms)

        # ── Extract JS files, static assets, and hidden links ────────────
        for js in _extract_js_files(soup, current_url):
            js_files.add(js)
        for asset in _extract_assets(soup, current_url):
            assets.add(asset)
        for hidden in _extract_hidden_links(str(soup), current_url):
            hidden_links.add(hidden)
            if _is_same_domain(hidden, base_domain):
                if _is_api_url(hidden):
                    api_endpoints.add(hidden)

        # ── Extract API calls from inline + external JS ──────────────────
        for api_url in _extract_js_api_calls(soup, current_url):
            if _is_same_domain(api_url, base_domain):
                api_endpoints.add(api_url)
            # Also collect query params from JS API URLs
            for param in _extract_query_params(api_url):
                query_params.add(param)

        for api_url in _extract_linked_js_apis(soup, current_url, base_domain):
            if _is_same_domain(api_url, base_domain):
                api_endpoints.add(api_url)

        # ── Discover child links (BFS next level) ────────────────────────
        if depth < max_depth:
            child_links = _extract_links(soup, current_url)
            for link in child_links:
                if link not in visited and _is_same_domain(link, base_domain):
                    queue.append((link, depth + 1))
                    # Collect query params from discovered links too
                    for param in _extract_query_params(link):
                        query_params.add(param)

    # ── Deduplicate forms by action+method ────────────────────────────────────
    seen_forms: Set[str] = set()
    unique_forms: List[Dict[str, Any]] = []
    for form in all_forms:
        key = f"{form['method']}:{form['action']}"
        if key not in seen_forms:
            seen_forms.add(key)
            unique_forms.append(form)

    result = {
        "urls": sorted(set(all_urls)),
        "api_endpoints": sorted(api_endpoints),
        "forms": unique_forms,
        "query_params": sorted(query_params),
        # ── Advanced discovery (additive; older consumers ignore these) ──────
        "js_files": sorted(js_files),
        "assets": sorted(assets),
        "hidden_links": sorted(hidden_links),
        "robots": robots,
        "sitemap_urls": sorted(set(sitemap_urls)),
    }

    logger.info(
        "Crawl complete — %d URLs, %d API endpoints, %d forms, %d params, "
        "%d JS files, %d assets, %d hidden links",
        len(result["urls"]),
        len(result["api_endpoints"]),
        len(result["forms"]),
        len(result["query_params"]),
        len(result["js_files"]),
        len(result["assets"]),
        len(result["hidden_links"]),
    )
    return result

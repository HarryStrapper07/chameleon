Claude
































Readme · MD
🦎 Chameleon — Open Redirect Vulnerability Scanner
Chameleon is a fast, multi-threaded Python tool for discovering Open Redirect vulnerabilities. Give it a URL list, or just a bare domain and let it auto-recon (Wayback Machine + live crawl) on its own.

⚠️ Legal / Ethical use only. Only run this against targets you own or are explicitly authorized to test (e.g. a program in scope on a bug bounty platform). Unauthorized scanning of systems you don't have permission to test is illegal in most jurisdictions.

Features
✅ Works with a URL list (-l urls.txt) or just a domain (-u example.com)
✅ Auto-recon mode: pulls historical URLs from the Wayback Machine (CDX API) and does a lightweight live crawl of the target
✅ "Smart" param detection — in recon mode, only mutates params that actually look redirect-related, so you don't waste thousands of requests on ?id=, ?page=, etc. (--all-params to disable and test everything)
✅ 35+ bypass payloads: scheme confusion, subdomain/userinfo tricks, whitespace/control-char WAF bypasses, encoding tricks, JS/data URI sinks
✅ Multi-threaded scanning
✅ Colored terminal output
✅ Saves results to both .txt (human readable) and .csv (for further filtering)
Installation
bash
git clone https://github.com/<your-username>/chameleon.git
cd chameleon
pip install -r requirements.txt
Usage
Option 1 — You already have a URL list from recon
bash
python3 chameleon.py -l urls.txt -o results -d evil.com
Option 2 — You only have a domain (no list)
bash
python3 chameleon.py -u example.com -o results -d evil.com
Chameleon will:

Query the Wayback Machine for historical URLs of example.com
Crawl the live site for more URLs
Merge, dedupe, and prioritize redirect-looking params
Save the discovered URLs to results_discovered_urls.txt
Run the redirect tests on them
All options
bash
python3 chameleon.py -h
Flag	Description
-l, --list	File with target URLs (one per line)
-u, --target	Just a domain — auto-recon instead of a list
-o, --output	Output file prefix (default: chameleon_results)
-d, --domain	Attacker domain to test with (default: evil.com)
-t, --threads	Concurrent threads (default: 10)
--timeout	Request timeout in seconds (default: 8)
--all-params	Mutate every query param, not just redirect-like ones
--max-urls	[auto-recon] Max URLs to scan after recon (default: 300)
--crawl-pages	[auto-recon] Max pages to crawl live (default: 40)
Output
*_results.txt — human-readable report of vulnerable findings
*_results.csv — full data for every test (url, param, payload, status, location, vulnerable)
*_discovered_urls.txt — (auto-recon mode only) every URL Chameleon found
Disclaimer
This tool is intended for authorized security testing and bug bounty research only. The author(s) are not responsible for any misuse or damage caused by this tool.

License
MIT — see LICENSE


Claude is responding

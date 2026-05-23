#!/usr/bin/env python3
"""
SubFinder - Subdomain Enumeration Tool
For authorized security testing only.
"""

import argparse
import sys
import socket
import json
import csv
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "proxy", "vpn", "admin", "test",
    "dev", "staging", "api", "app", "beta", "cdn", "ci", "cloud", "dashboard",
    "db", "demo", "docs", "git", "help", "imap", "jenkins", "jira", "kibana",
    "log", "m", "media", "mobile", "monitor", "mx", "mx1", "mx2", "news",
    "ntp", "old", "panel", "portal", "redis", "remote", "repo", "rest",
    "search", "secure", "server", "smtp", "sql", "ssh", "ssl", "static",
    "status", "store", "support", "syslog", "test", "tools", "uat", "upload",
    "vpn", "web", "wiki", "wordpress", "ws", "zabbix", "grafana", "elastic",
    "kafka", "rabbit", "mongo", "mysql", "postgres", "oracle", "mssql",
    "backup", "bak", "bkp", "archive", "old", "legacy", "new", "stage",
    "uat", "qa", "pre", "prod", "production", "development", "sandbox",
    "auth", "sso", "login", "ldap", "okta", "oauth", "id", "identity",
    "intranet", "internal", "corp", "corporate", "office", "hr", "payroll",
    "erp", "crm", "sales", "marketing", "finance", "accounting", "billing",
    "shop", "ecommerce", "cart", "checkout", "payment", "pay", "gateway",
    "cdn", "assets", "images", "img", "js", "css", "fonts", "static",
    "files", "download", "downloads", "dl", "mirror", "edge", "node",
    "worker", "job", "queue", "cache", "memcached", "session", "log",
    "logs", "logging", "syslog", "audit", "monitor", "health", "ping",
    "check", "status", "stats", "metrics", "analytics", "tracking",
    "feedback", "survey", "form", "forms", "contact", "support", "help",
    "faq", "kb", "knowledge", "docs", "documentation", "wiki", "guide",
]


class SubdomainFinder:
    def __init__(self, domain, threads=50):
        self.domain = domain
        self.threads = threads
        self.found = set()
        self.lock = threading.Lock()

    def is_wildcard(self):
        """Check if domain has wildcard DNS."""
        import random
        import string
        rand = ''.join(random.choices(string.ascii_lowercase, k=16))
        try:
            socket.gethostbyname(f"{rand}.{self.domain}")
            return True
        except socket.gaierror:
            return False

    def resolve_subdomain(self, subdomain):
        """Check if subdomain resolves."""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            with self.lock:
                self.found.add((fqdn, ip))
            return fqdn, ip
        except socket.gaierror:
            return None, None

    def dns_brute(self, wordlist):
        """DNS brute-force enumeration."""
        print(f"\n{Fore.CYAN}[*] DNS Brute-Force: {self.domain}{Style.RESET_ALL}")

        # Check wildcard
        if self.is_wildcard():
            print(f"  {Fore.YELLOW}[!] Wildcard DNS detected - results may include false positives{Style.RESET_ALL}")

        print(f"  {Fore.CYAN}[*] Testing {len(wordlist)} subdomains with {self.threads} threads...{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.resolve_subdomain, sub): sub for sub in wordlist}
            for future in as_completed(futures):
                fqdn, ip = future.result()
                if fqdn:
                    print(f"  {Fore.GREEN}[+] {fqdn} => {ip}{Style.RESET_ALL}")

        return self.found

    def ct_search(self):
        """Search Certificate Transparency logs."""
        if not HAS_REQUESTS:
            print(f"  {Fore.RED}[!] requests library required for CT search{Style.RESET_ALL}")
            return set()

        print(f"\n{Fore.CYAN}[*] Searching Certificate Transparency logs...{Style.RESET_ALL}")

        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                domains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for d in name.split("\n"):
                        d = d.strip().lower()
                        if d.endswith(self.domain) and "*" not in d:
                            domains.add(d)

                print(f"  {Fore.GREEN}[+] Found {len(domains)} unique domains from CT logs{Style.RESET_ALL}")

                for d in sorted(domains):
                    try:
                        ip = socket.gethostbyname(d)
                        with self.lock:
                            self.found.add((d, ip))
                        print(f"  {Fore.GREEN}[+] {d} => {ip}{Style.RESET_ALL}")
                    except:
                        print(f"  {Fore.YELLOW}[?] {d} (no DNS resolution){Style.RESET_ALL}")

        except Exception as e:
            print(f"  {Fore.RED}[!] CT search error: {e}{Style.RESET_ALL}")

        return self.found

    def search_engine_search(self):
        """Search for subdomains via search engines."""
        if not HAS_REQUESTS:
            print(f"  {Fore.RED}[!] requests library required for search engine search{Style.RESET_ALL}")
            return set()

        print(f"\n{Fore.CYAN}[*] Search Engine Enumeration...{Style.RESET_ALL}")

        engines = [
            ("Google", f"https://www.google.com/search?q=site:*.{self.domain}&num=100"),
            ("Bing", f"https://www.bing.com/search?q=site:*.{self.domain}&count=50"),
        ]

        import re
        for name, url in engines:
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                resp = requests.get(url, headers=headers, timeout=10)
                found = re.findall(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(self.domain) + r')', resp.text)
                unique = set(f.lower() for f in found if "*" not in f)
                for d in unique:
                    try:
                        ip = socket.gethostbyname(d)
                        with self.lock:
                            self.found.add((d, ip))
                        print(f"  {Fore.GREEN}[+] {d} => {ip}{Style.RESET_ALL}")
                    except:
                        pass
            except Exception as e:
                print(f"  {Fore.YELLOW}[!] {name} search error: {e}{Style.RESET_ALL}")

        return self.found

    def dns_records(self, record_types=None):
        """Query DNS records for the domain."""
        if not HAS_REQUESTS:
            print(f"  {Fore.RED}[!] requests library required for DNS record queries{Style.RESET_ALL}")
            return {}

        if record_types is None:
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        print(f"\n{Fore.CYAN}[*] DNS Records for {self.domain}:{Style.RESET_ALL}")
        records = {}

        for rtype in record_types:
            try:
                url = f"https://dns.google/resolve?name={self.domain}&type={rtype}"
                resp = requests.get(url, timeout=10)
                data = resp.json()
                answers = data.get("Answer", [])
                if answers:
                    records[rtype] = [a.get("data", "") for a in answers]
                    print(f"\n  {Fore.WHITE}{rtype} Records:{Style.RESET_ALL}")
                    for a in answers:
                        print(f"    {a.get('data', '')} (TTL: {a.get('TTL', 'N/A')})")
            except:
                pass

        return records

    def export(self, filename, fmt="json"):
        """Export results."""
        results = [{"subdomain": sub, "ip": ip} for sub, ip in sorted(self.found)]

        if fmt == "json":
            report = {
                "tool": "SubFinder",
                "version": VERSION,
                "domain": self.domain,
                "scan_time": datetime.now().isoformat(),
                "total_found": len(results),
                "subdomains": results,
            }
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)

        elif fmt == "csv":
            with open(filename, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["Subdomain", "IP Address"])
                for r in results:
                    w.writerow([r["subdomain"], r["ip"]])

        elif fmt == "text":
            with open(filename, 'w') as f:
                for r in results:
                    f.write(f"{r['subdomain']} => {r['ip']}\n")

        print(f"\n{Fore.GREEN}[+] Results exported to {filename}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="SubFinder - Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s enumerate example.com
  %(prog)s brute example.com -w wordlist.txt
  %(prog)s ct example.com
  %(prog)s full example.com --output json --file results.json
  %(prog)s dns example.com --records A,MX,NS
        """
    )

    sub = parser.add_subparsers(dest="command")

    # enumerate
    enum_cmd = sub.add_parser("enumerate", help="Enumerate subdomains (CT + search engines)")
    enum_cmd.add_argument("domain", help="Target domain")

    # brute
    brute_cmd = sub.add_parser("brute", help="DNS brute-force enumeration")
    brute_cmd.add_argument("domain", help="Target domain")
    brute_cmd.add_argument("-w", "--wordlist", help="Subdomain wordlist file")
    brute_cmd.add_argument("--threads", type=int, default=50, help="Thread count")

    # ct
    ct_cmd = sub.add_parser("ct", help="Certificate Transparency search")
    ct_cmd.add_argument("domain", help="Target domain")

    # full
    full_cmd = sub.add_parser("full", help="Full enumeration (all methods)")
    full_cmd.add_argument("domain", help="Target domain")
    full_cmd.add_argument("-w", "--wordlist", help="Subdomain wordlist file")
    full_cmd.add_argument("--threads", type=int, default=50, help="Thread count")
    full_cmd.add_argument("--output", choices=["json", "csv", "text"], help="Export format")
    full_cmd.add_argument("--output-file", help="Output filename")

    # dns
    dns_cmd = sub.add_parser("dns", help="Query DNS records")
    dns_cmd.add_argument("domain", help="Target domain")
    dns_cmd.add_argument("--records", default="A,AAAA,MX,NS,TXT,CNAME,SOA",
                         help="Comma-separated record types")

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════╗")
    print(f"║    SubFinder v{VERSION}             ║")
    print(f"╚══════════════════════════════════╝{Style.RESET_ALL}")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    domain = args.domain.lower().replace("http://", "").replace("https://", "").rstrip("/")

    if args.command == "dns":
        finder = SubdomainFinder(domain)
        finder.dns_records(args.records.split(","))
        return

    finder = SubdomainFinder(domain, getattr(args, 'threads', 50))

    if args.command in ("brute", "full"):
        wordlist = DEFAULT_WORDLIST
        if args.wordlist:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
        finder.dns_brute(wordlist)

    if args.command in ("enumerate", "full"):
        finder.ct_search()
        finder.search_engine_search()

    # Summary
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"  SUMMARY: {domain}")
    print(f"  Total subdomains found: {len(finder.found)}")
    print(f"{'='*50}{Style.RESET_ALL}")

    for sub, ip in sorted(finder.found):
        print(f"  {Fore.GREEN}{sub}{Style.RESET_ALL} => {ip}")

    if args.command == "full" and args.output:
        ext = {"json": ".json", "csv": ".csv", "text": ".txt"}
        outfile = args.output_file or f"subdomains_{domain}{ext[args.output]}"
        finder.export(outfile, args.output)


if __name__ == "__main__":
    main()

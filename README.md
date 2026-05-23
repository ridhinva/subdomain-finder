# SubFinder - Subdomain Enumeration Tool

Discovers subdomains of a target domain using multiple techniques including DNS brute-force, certificate transparency logs, and search engine scraping.

## Features

- DNS brute-force enumeration
- Certificate Transparency (CT) log queries
- Search engine scraping (Google, Bing, DuckDuckGo)
- DNS record analysis (A, AAAA, CNAME, MX, NS, TXT)
- Wildcard detection
- Multi-threaded enumeration
- JSON/CSV/text output

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/subdomain-finder.git
cd subdomain-finder
pip3 install -r requirements.txt
chmod +x subfinder.py
```

## Usage

### Basic Subdomain Enumeration
```bash
python3 subfinder.py enumerate example.com
```

### DNS Brute-Force
```bash
python3 subfinder.py brute example.com
python3 subfinder.py brute example.com -w wordlist.txt
python3 subfinder.py brute example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Certificate Transparency Search
```bash
python3 subfinder.py ct example.com
```

### Combined Enumeration
```bash
python3 subfinder.py full example.com --output json --file results.json
```

### DNS Records
```bash
python3 subfinder.py dns example.com
python3 subfinder.py dns example.com --records A,AAAA,MX,NS,TXT,CNAME
```

### Export Results
```bash
python3 subfinder.py full example.com --output json --file subs.json
python3 subfinder.py full example.com --output csv --file subs.csv
python3 subfinder.py full example.com --output text --file subs.txt
```

## Legal Disclaimer

Only enumerate subdomains on domains you own or have authorization to test.

## License

MIT License

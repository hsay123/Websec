import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
import json
import re
from colorama import Fore, Style, init

init(autoreset=True)

# Payloads for testing
XSS_PAYLOADS = ['<script>alert(1)</script>', '" onmouseover="alert(1)']
SQLI_PAYLOADS = ["' OR '1'='1", '" OR "1"="1']

# Common security headers
SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Permissions-Policy",
    "Referrer-Policy"
]

# Explanations for security headers
HEADER_EXPLANATIONS = {
    "X-Content-Type-Options": "Prevents MIME-sniffing. Helps prevent some XSS attacks.",
    "X-Frame-Options": "Prevents clickjacking by disallowing site from being embedded in iframes.",
    "Strict-Transport-Security": "Enforces HTTPS connections, prevents downgrade attacks.",
    "Content-Security-Policy": "Restricts resources (JS, CSS, etc.) to prevent XSS.",
    "Permissions-Policy": "Restricts access to browser features like camera, microphone, etc.",
    "Referrer-Policy": "Controls how much referrer info is sent with requests."
}

visited = set()
results = {"headers": {}, "cookies": {}, "xss": {}, "sqli": {}}

def check_headers(url):
    try:
        r = requests.get(url, timeout=5)
        missing = []
        for header in SECURITY_HEADERS:
            if header not in r.headers:
                explanation = HEADER_EXPLANATIONS.get(header, "No description available.")
                missing.append(f"{header}: {explanation}")
        if missing:
            print(Fore.YELLOW + f"\n[HEADERS] {url} -> Missing security headers:")
            for item in missing:
                print(Fore.LIGHTYELLOW_EX + f"  - {item}")
            results["headers"][url] = missing
    except Exception as e:
        print(Fore.RED + f"[ERROR] {url}: {e}")

def check_cookies(url):
    try:
        r = requests.get(url, timeout=5)
        cookies = r.cookies
        issues = []
        for c in cookies:
            if not c.secure:
                issues.append(f"{c.name} missing Secure flag")
            if "httponly" not in str(c._rest).lower():
                issues.append(f"{c.name} missing HttpOnly flag")
        if issues:
            print(Fore.YELLOW + f"[COOKIES] {url} -> {'; '.join(issues)}")
            results["cookies"][url] = issues
    except:
        pass

def check_xss(url):
    parsed = urlparse(url)
    if not parsed.query:
        return
    params = parse_qs(parsed.query)
    for p in params:
        for payload in XSS_PAYLOADS:
            test_url = url.replace(params[p][0], payload)
            try:
                r = requests.get(test_url, timeout=5)
                if payload in r.text:
                    print(Fore.RED + f"[XSS] {test_url} -> Payload reflected!")
                    results["xss"][test_url] = payload
            except:
                pass

def check_sqli(url):
    parsed = urlparse(url)
    if not parsed.query:
        return
    params = parse_qs(parsed.query)
    for p in params:
        for payload in SQLI_PAYLOADS:
            test_url = url.replace(params[p][0], payload)
            try:
                r = requests.get(test_url, timeout=5)
                if re.search(r"SQL|syntax|mysql|ora", r.text, re.I):
                    print(Fore.RED + f"[SQLi] {test_url} -> SQL error detected!")
                    results["sqli"][test_url] = payload
            except:
                pass

def crawl(url, domain, max_depth=2, depth=0):
    if depth > max_depth or url in visited:
        return
    visited.add(url)
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        links = [urljoin(url, a.get("href")) for a in soup.find_all("a", href=True)]
        for link in links:
            if urlparse(link).netloc == domain:
                crawl(link, domain, max_depth, depth+1)
                run_checks(link)
    except:
        pass

def run_checks(url):
    check_headers(url)
    check_cookies(url)
    check_xss(url)
    check_sqli(url)

def save_report():
    # Save JSON report
    with open("report.json", "w") as f:
        json.dump(results, f, indent=4)

    # Save HTML report
    with open("report.html", "w") as f:
        f.write("<h1>Web Security Scan Report</h1>")
        for cat, issues in results.items():
            f.write(f"<h2>{cat.upper()}</h2><ul>")
            for url, details in issues.items():
                f.write(f"<li><b>{url}</b><ul>")
                if isinstance(details, list):
                    for item in details:
                        f.write(f"<li>{item}</li>")
                else:
                    f.write(f"<li>{details}</li>")
                f.write("</ul></li>")
            f.write("</ul>")

if __name__ == "__main__":
    target = input("Enter target URL (with https://): ").strip()
    domain = urlparse(target).netloc
    print(Fore.CYAN + f"[*] Starting scan on {target}")
    crawl(target, domain)
    save_report()
    print(Fore.GREEN + "[+] Scan complete! Results saved to report.json and report.html")

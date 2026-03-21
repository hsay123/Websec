# 🔒 WebSec - Web Security Testing Tool

A lightweight Python-based web security scanner that performs basic vulnerability assessments on target websites. It checks for:

- 🔐 Missing security headers
- 🍪 Insecure cookies (no Secure / HttpOnly flags)
- 💉 Reflected XSS vulnerabilities
- 🧬 SQL Injection detection
- 🌐 Recursive link crawling (depth-limited)

---

## 🚀 Features

- Color-coded console output (via `colorama`)
- Generates HTML + JSON reports
- Easy to use, beginner-friendly
- Works on any public-facing website

---

## 🧰 Dependencies

Install Python 3 (recommended: ≥ 3.7) and install the required packages:

```bash
pip install -r requirements.txt


📂 Folder Structure
websec/
├── websec.py          # Main scanner script
├── report.json        # Output JSON report (auto-generated)
├── report.html        # Output HTML report (auto-generated)
├── README.md          # You're reading this
└── requirements.txt   # Python dependencies
```
<div align="center">
  <img src="Screenshot From 2026-03-21 22-52-47.png" width="800" alt="System Architecture"/>
</div>
```


⚙️ Usage
1. Clone the Repository
git clone https://github.com/<your-username>/websec-tool.git
cd websec-tool

2. Run the Scanner
python3 websec.py


You’ll be prompted to enter a target URL (must include https://):

Enter target URL (with https://): https://example.com

3. Output

report.json: structured output for developers

report.html: formatted report for browsers

Console: real-time color-coded alerts

📊 Sample Output
[HEADERS] https://target.com -> Missing security headers:
  - X-Frame-Options: Prevents clickjacking by disallowing site from being embedded in iframes.
  - Content-Security-Policy: Restricts resources (JS, CSS, etc.) to prevent XSS.

[COOKIES] https://target.com -> sessionid missing Secure flag; sessionid missing HttpOnly flag

[XSS] https://target.com/page?input=<script>alert(1)</script> -> Payload reflected!

[SQLi] https://target.com/login?user=' OR '1'='1 -> SQL error detected!

🛡️ Disclaimers

Educational Use Only: Do not scan websites you do not own or have permission to test.

This tool performs non-intrusive checks only — no exploitation is attempted.

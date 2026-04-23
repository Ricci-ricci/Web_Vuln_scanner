# Web Vulnerability Scanner

A Python-based web vulnerability scanner. It crawls a target website, tests it for common
security weaknesses — missing headers, XSS, SQL injection, open redirects, directory listing,
and SSL/TLS issues — and prints a report in the terminal or exports it to JSON or HTML.

Built as a portfolio project.

---

## Disclaimer

This tool is for educational and authorised security testing only.

Scanning any system without explicit written permission from the owner is illegal in most
countries. The author takes no responsibility for any misuse or damage caused by this tool.
By using it, you accept full responsibility for your actions.

**Only scan systems you own or have been given permission to test.**

---

## Usage

**Install dependencies**
```bash
pip install -r requirements.txt

Scan a target**

python -m scanner scan https://example.com


**Run specific modules only**

python -m scanner scan https://example.com --modules headers,xss,sqli

**Export to JSON**

python -m scanner scan https://example.com --output json --report reports/result.json


**Export to HTML**

python -m scanner scan https://example.com --output html --report reports/result.html


**List available modules**

python -m scanner list-modules


**All options**

--modules     Comma-separated list of modules to run (default: all)
--output      Output format: json or html
--report      File path for the exported report
--depth       How many links deep the crawler follows (default: 3)
--max-pages   Maximum number of pages to crawl (default: 200)
--timeout     HTTP request timeout in seconds (default: 10)

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

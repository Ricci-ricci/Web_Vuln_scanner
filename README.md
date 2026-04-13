# 🔍 Web Vulnerability Scanner

A Python-based web vulnerability scanner built for educational purposes and portfolio demonstration.
It automatically crawls a target web application and audits it for common security misconfigurations
and vulnerabilities, generating a detailed report of its findings.

---

## ⚠️ Legal Disclaimer

> **This tool is intended strictly for educational and authorized security testing purposes only.**
>
> Scanning a web application or system **without explicit written permission** from the owner is
> **illegal** in most jurisdictions and may violate laws such as the Computer Fraud and Abuse Act
> (CFAA), the UK Computer Misuse Act, or equivalent legislation in your country.
>
> The author of this project accepts **no responsibility or liability** for any misuse, damage, or
> legal consequences resulting from the use of this tool. By using this software, you agree that
> you are solely responsible for your actions and that you have obtained all necessary authorizations
> before running any scan.
>
> **Only use this tool against systems you own or have been explicitly authorized to test.**
> If in doubt, don't scan it.

---

## 📖 Overview

Modern web applications are complex and often ship with security gaps that are easy to overlook —
missing HTTP headers, unvalidated user inputs, outdated TLS configurations, and more. This scanner
automates the detection of those gaps so developers and security practitioners can identify and fix
them before a malicious actor does.

This project was built as a portfolio piece to demonstrate practical knowledge in:

- Web application security concepts (OWASP Top 10)
- Python software architecture and design patterns
- HTTP internals and browser security mechanisms
- Automated testing and reporting pipelines

---

## ✨ Features

| Module | What it checks |
|---|---|
| **Security Headers** | Detects missing headers such as `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, etc. |
| **XSS Detection** | Injects payloads into GET/POST parameters and form fields to detect reflected Cross-Site Scripting. |
| **SQL Injection** | Tests inputs with error-based and boolean-based payloads to surface potential SQLi vulnerabilities. |
| **Open Redirect** | Identifies parameters that blindly redirect users to arbitrary external URLs. |
| **Directory Listing** | Discovers exposed directory indexes that reveal server file structure. |
| **SSL/TLS Audit** | Checks certificate validity, expiry, and protocol version weaknesses. |

Additional capabilities:

- **Built-in Spider** — automatically crawls the target to discover pages, links, and forms before scanning.
- **Severity Ratings** — every finding is rated `Low`, `Medium`, `High`, or `Critical`.
- **Multiple Output Formats** — results can be displayed in the terminal or exported to JSON and HTML.
- **Modular Architecture** — new vulnerability modules can be added with minimal boilerplate.

---

## 🏗️ Architecture

The project is organized around a simple pipeline:

```
CLI → Engine → Spider → Modules → Reporter
```

1. **CLI** — parses user arguments (target URL, modules to run, output format, etc.)
2. **Engine** — orchestrates the scan: initializes the HTTP client, runs the spider, then dispatches each module.
3. **Spider** — crawls the target application to build a list of URLs, query parameters, and HTML forms.
4. **Modules** — each module receives the crawled endpoints and independently tests for a specific class of vulnerability.
5. **Reporter** — aggregates all findings from every module and renders them to the terminal or an export file.

Every module inherits from a common `BaseModule` interface, making the system easy to extend. A finding
produced by any module always contains: the affected URL, a severity level, a description of the issue,
the evidence observed (payload, header value, etc.), and a suggested remediation step.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| HTTP Client | `httpx` (async) |
| HTML Parsing | `beautifulsoup4` |
| CLI | `typer` + `rich` |
| Data Models | `pydantic` v2 |
| HTML Reports | `jinja2` |
| Testing | `pytest` + `pytest-httpx` |

---

## 🚀 Usage

```bash
# Scan a target with all modules
python -m scanner scan https://example.com

# Scan with specific modules only
python -m scanner scan https://example.com --modules xss,sqli,headers

# Export results to JSON
python -m scanner scan https://example.com --output json --report reports/result.json

# Export results to HTML
python -m scanner scan https://example.com --output html --report reports/result.html
```

---

## 📁 Project Structure

```
web_vuln_scanner/
├── scanner/
│   ├── cli.py                # Entry point
│   ├── core/
│   │   ├── engine.py         # Scan orchestrator
│   │   ├── http_client.py    # HTTP session wrapper
│   │   └── target.py         # Target model
│   ├── crawler/
│   │   └── spider.py         # Link and form crawler
│   ├── modules/
│   │   ├── base.py           # BaseModule interface
│   │   ├── xss.py
│   │   ├── sqli.py
│   │   ├── headers.py
│   │   ├── open_redirect.py
│   │   ├── directory_listing.py
│   │   └── ssl_tls.py
│   ├── report/
│   │   ├── models.py         # Finding / Report dataclasses
│   │   ├── console.py        # Rich terminal output
│   │   └── exporter.py       # JSON / HTML export
│   └── utils/
│       ├── logger.py
│       └── helpers.py
├── tests/
├── reports/
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

```bash
git clone https://github.com/your-username/web_vuln_scanner.git
cd web_vuln_scanner
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
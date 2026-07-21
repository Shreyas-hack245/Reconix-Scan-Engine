# 🛡️ Reconix Scan Engine

**Reconix Scan Engine** is an AI-powered web application security scanner that automates the discovery of common web vulnerabilities through intelligent crawling, safe vulnerability validation, AI-assisted analysis, and comprehensive reporting.

Designed for penetration testers, security researchers, developers, and security teams, Reconix Scan Engine focuses on **accurate detection, low false positives, safe proof-of-concept validation, and actionable remediation guidance**.

---

> ⚠️ **Disclaimer:** This project is intended for **authorized security assessments, defensive security research, and educational purposes only.** Only scan systems that you own or have explicit permission to test.

---

# ✨ Features

- 🌐 Intelligent website crawling and endpoint discovery
- 📝 HTML form extraction
- 🔍 JavaScript endpoint discovery
- 🤖 OpenAPI / Swagger endpoint parsing
- 🛡️ Robots.txt & Sitemap parsing

### Vulnerability Detection

- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Server-Side Request Forgery (SSRF)
- Remote Code Execution (Safe Detection)
- Command Injection
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object Reference (IDOR)
- Broken Access Control
- Security Header Analysis
- Cookie Security Analysis
- CORS Misconfiguration
- Open Redirect
- File Upload Vulnerabilities
- Directory Traversal
- Information Disclosure
- Clickjacking Detection

---

# 🤖 AI-Powered Analysis

Every detected finding is enriched with:

- AI-generated vulnerability explanation
- Business impact assessment
- Attack scenario overview
- Confidence scoring
- OWASP Top 10 mapping
- CVSS scoring
- Safe Proof-of-Concept (PoC)
- Step-by-step remediation guidance

---

# 📊 Reporting

Generate reports in multiple formats:

- HTML Report
- PDF Report
- Markdown Report
- JSON Report

Each report includes:

- Executive Summary
- Risk Distribution
- Technical Findings
- Safe PoCs
- Remediation Recommendations
- OWASP Mapping
- CVSS Scores
- Complete Audit Trail

---

# 🔐 Security Features

- JWT Authentication
- Role-Based Access Control (RBAC)
- Rate Limiting
- Request Audit Logging
- Scan History
- Safe Validation Techniques
- Non-Destructive Security Testing

---

# 🛠️ Tech Stack

### Backend

- FastAPI
- SQLAlchemy
- Pydantic
- HTTPX
- Playwright
- BeautifulSoup4
- LXML
- SQLite / PostgreSQL

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS

### Reporting

- Jinja2
- WeasyPrint
- Markdown2

---

# 🚀 Installation

## Backend

```bash
cd backend

python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env

uvicorn app.main:app --reload
```

Backend:

```
http://127.0.0.1:8000
```

API Documentation:

```
http://127.0.0.1:8000/docs
```

---

## Frontend

```bash
cd frontend

npm install

npm run dev
```

Frontend:

```
http://localhost:5173
```

---

# 🧪 Running Tests

```bash
cd backend

pytest
```

---

# 📂 Reports

Reconix Scan Engine can export findings as:

- HTML
- PDF
- JSON
- Markdown

Reports include:

- Executive Summary
- Technical Findings
- Safe Proof-of-Concepts
- Severity Classification
- OWASP Mapping
- CVSS Scores
- Remediation Steps
- Audit Trail

---

# 📌 Roadmap

- ✅ Intelligent Crawling
- ✅ Vulnerability Detection Engine
- ✅ AI Risk Analysis
- ✅ Safe PoC Generation
- ✅ Reporting Engine
- ✅ React Dashboard
- ✅ Authentication & RBAC
- ✅ Audit Logging
- ✅ Automated Testing

---


# 📄 License

This project is licensed under the **MIT License**.

---

# ⚠️ Legal Notice

Reconix Scan Engine is intended solely for **authorized penetration testing, security research, and educational purposes**.

The developers assume **no responsibility** for misuse or unauthorized use of this software. Always obtain proper authorization before scanning any system.

# Reconix Scan Engine

Reconix Scan Engine is an AI-powered web application security scanner that helps identify common web vulnerabilities through safe and automated testing.

## Features

- Automated website crawling
- Vulnerability scanning
- Safe PoC validation
- AI-powered vulnerability explanations
- Risk-based findings
- HTML, PDF, Markdown & JSON reports
- Audit trail of performed tests

## Project layout

```
backend/    FastAPI application: crawler, scanner modules, AI
            enrichment, reporting engine, JWT auth, SQLite database
frontend/   React + TypeScript + Tailwind dashboard
docs/       Architecture notes and additional documentation
```

## Quick start (without Docker)

### Backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then set SECRET_KEY to a random value
uvicorn app.main:app --reload
```

- API docs: http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/health

Register a user and log in via `/docs` (or the frontend below), then
use `POST /api/scans/` to launch a scan against a target you're
authorized to test.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

- Dashboard: http://localhost:5173 (proxies `/api` to the backend on port 8000)

## Quick start (with Docker)

```bash
docker compose up --build
```

- Frontend: http://localhost:8080
- Backend: http://localhost:8000

## Running tests

```bash
cd backend
pytest
```

Tests use `httpx.MockTransport` to simulate target servers, so they run
fully offline with no real network requests.

## Further reading

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a walkthrough of
the scan pipeline (crawl -> scan -> AI enrichment -> report) and the
data model, and [`docs/README.md`](docs/README.md) for a more detailed
usage guide (API walkthrough, adding a new scanner module, report
formats).

## Status

🚧 Currently under development.
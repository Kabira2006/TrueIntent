# TrueIntent

[![CI](https://github.com/Kabira2006/TrueIntent/actions/workflows/ci.yml/badge.svg)](https://github.com/Kabira2006/TrueIntent/actions/workflows/ci.yml)

TrueIntent is a research prototype that examines links, UPI payment links, and QR text and reports explainable indicators rather than a final judgment.

## Quick start

The web app, API, PostgreSQL, Redis, and background worker are in
[`link-security-analyzer/`](link-security-analyzer/). From that directory:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Open `http://localhost:3000` for the frontend or
`http://localhost:8000/docs` for the API documentation. The frontend submits
inputs and polls the API's returned `poll_url` for the persisted three-pillar
report. A placeholder such as `https://example.com` can be used for a demo.

```powershell
$accepted = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8000/api/v1/scan" `
  -ContentType "application/json" `
  -Body (@{ input = "https://example.com" } | ConvertTo-Json)
Invoke-RestMethod -Uri $accepted.poll_url
```

To run the backend tests, change to
`link-security-analyzer/backend/` and run `python -m pytest -q`. The
evaluation tools and their limitations are described in
[`link-security-analyzer/README.md`](link-security-analyzer/README.md).

## Project journal
Progress and plain-language explanations live in
[`docs/PROJECT_JOURNAL.md`](docs/PROJECT_JOURNAL.md). The latest chapter states
which parts of the prototype were and were not verified.

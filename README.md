# TrueIntent

TrueIntent is a research prototype that examines links, UPI payment links, and QR text and reports explainable indicators rather than a final judgment.

## Quick start

The API and its PostgreSQL, Redis, and background-worker dependencies are in
[`link-security-analyzer/`](link-security-analyzer/). From that directory:

```powershell
Copy-Item .env.example .env
docker compose up --build postgres redis backend worker
```

Then open `http://localhost:8000/docs` for the API documentation. Submit a
placeholder link such as `https://example.com` to `POST /api/v1/scan` and poll
the returned `poll_url` with `GET`. The Next.js interface has not been
implemented yet; the Compose frontend service is still a placeholder, so this
quick start is for the API only.

```powershell
$accepted = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8000/api/v1/scan" `
  -ContentType "application/json" `
  -Body (@{ input = "https://example.com" } | ConvertTo-Json)
Invoke-RestMethod -Uri ("http://localhost:8000" + $accepted.poll_url)
```

To run the backend tests, change to
`link-security-analyzer/backend/` and run `python -m pytest -q`. The
evaluation tools and their limitations are described in
[`link-security-analyzer/README.md`](link-security-analyzer/README.md).

## Project journal
Progress and plain-language explanations live in
[`docs/PROJECT_JOURNAL.md`](docs/PROJECT_JOURNAL.md). The latest chapter states
which parts of the prototype were and were not verified.

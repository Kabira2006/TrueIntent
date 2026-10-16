# TrueIntent

TrueIntent helps people spot scam links, UPI payment links, and QR codes by showing explainable risk indicators, never a final verdict.

Module A (`link-security-analyzer/`) takes a URL, UPI deep link, or pasted QR text and reports clues across three pillars: technical URL analysis, visual brand analysis, and transaction context. Other modules (text scam engine, screenshot OCR, call audio) will be added later as sibling folders.

See `AGENTS.md` for contributor rules. Infra and app code lands in later chunks; Chunk 0 only sets up rules, the empty skeleton, and the journal.

## Project journal
Progress and plain-words explanations live in [docs/PROJECT_JOURNAL.md](docs/PROJECT_JOURNAL.md). Start with Chapter 0.

# Multi‑Agent LLM Cyber Threat‑Detection

A minimal yet extensible proof‑of‑concept that shows how a **LangGraph + LLM‑supervised tool‑calling** workflow can detect potential cyber threats from streamed log events.

## Features

| Agent / Tool | Purpose |
|--------------|---------|
| `event_analysis` | Heuristic scoring of every incoming event (rules table, 0‑100) |
| `sql_lookup`     | Counts recent login failures / successes from a local SQLite `logins` table |
| `threat_intel`   | Queries AbuseIPDB for IP reputation (requires free API key) |
| `web_search`     | Context‑aware DuckDuckGo search (IP reputation, attack patterns, CVEs) |
| `notify`         | Appends an alert entry to a per‑model log file (see `alerts-*.log`) |

## Architecture

```
stream → main.py  ──► LangGraph supervisor (Groq model w/ tool calling)
                     │
                     ├─ event_analysis ─┐
                     │                 ├── conditional sql_lookup
                     │                 ├── conditional threat_intel
                     │                 ├── conditional web_search
                     │                 └── notify ➜ alerts-<model>.log
                     ▼
                plain‑English summary
```

## Dataset

This repo uses the **Login Data Set for Risk‑Based Authentication (RBA)** shape (IP, user agent, country, login success, etc.).

- **Sample included**: `rba-dataset.csv` (small CSV sample committed to the repo for quick testing)
- **Ingestion code**: `events_feed.py` reads the CSV and maps it into the internal `Event` schema.
- **Testing limit**: by default the runner processes **10 rows max** (configurable via `SAMPLE_LIMIT`).

## Quick‑start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export GROQ_API_KEY="<your key>"     # Groq
export ABUSE_IP_DB="<your key>"      # AbuseIPDB (optional but recommended)

# Use the repo's sample CSV by default; override if needed:
# export RBA_CSV_PATH="/path/to/rba-dataset.csv"

# Process at most 10 rows (default is 10)
export SAMPLE_LIMIT=10
python main.py
```

After running, you should see per‑model outputs like:
- `alerts-openai-gpt-oss-120b.log`
- `alerts-llama-3.1-8b-instant.log`
- `alerts-qwen-qwen3-32b.log`

## Customising

* **Rules** – edit `tools/event_analysis.py` RULES list.
* **DB seed** – run without seeding by default; set `SEED_DUMMY_LOGINS=1` if you want dummy rows (see `setups/create_logs_db.py`).
* **Thresholds / policy** – tweak the `SYSTEM_PROMPT` in `main.py`.
* **Additional tools** – just drop a new callable in `tools/` and add it to `TOOLS`.

## Limitations

* AbuseIPDB calls are live; heavy demos may hit free‑tier rate limits.
* DuckDuckGo search can also rate‑limit; the tool now fails gracefully.
* No persistence between runs except the SQLite file seeded on first launch.


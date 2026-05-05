# Multi‑Agent LLM Cyber Threat‑Detection

A minimal yet extensible proof‑of‑concept that shows how a **LangGraph + LLM‑supervised tool‑calling** workflow can detect potential cyber threats from streamed log events. Includes an optional **lightweight ML anomaly detector** as a pre-screener to improve scalability and reduce API costs.

## Features

| Component | Purpose |
|-----------|---------|
| **ML Pre-screener** (optional) | Lightweight unsupervised anomaly detection using Isolation Forest |
| `event_analysis` | Heuristic scoring of every incoming event (rules table, 0‑100) |
| `sql_lookup`     | Counts recent login failures / successes from a local SQLite `logins` table |
| `threat_intel`   | Queries AbuseIPDB for IP reputation (requires free API key) |
| `web_search`     | Context‑aware DuckDuckGo search (IP reputation, attack patterns, CVEs) |
| `notify`         | Appends an alert entry to a per‑model log file (see `alerts-*.log`) |

## Architecture

```
CSV stream ──► [ML Pre-screener] ──► main.py ──► LangGraph supervisor (Groq model w/ tool calling)
               (Isolation Forest)              │
               adds ml_anomaly_score           ├─ event_analysis ─┐
               adds ml_is_anomaly              │                 ├── conditional sql_lookup
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

### With ML Anomaly Detection (Optional)

To enable the lightweight ML pre-screener:

1. **Train the anomaly model** (on your larger dataset):
   ```bash
   # Train on rba-dataset-milrow.csv (or your own dataset)
   python train_anomaly_model.py
   ```

2. **Run with ML enabled**:
   ```bash
   export ENABLE_ML_ANOMALY=1
   export ANOMALY_MODEL_PATH="data/anomaly_model.joblib"
   export ANOMALY_THRESHOLD=0.0  # Higher = more selective
   python main.py
   ```

The ML model adds `ml_anomaly_score` and `ml_is_anomaly` fields to each event before it reaches the LLM supervisor.

After running, you should see per‑model outputs like:
- `alerts-openai-gpt-oss-120b.log`
- `alerts-llama-3.1-8b-instant.log`
- `alerts-qwen-qwen3-32b.log`

## Customising

* **Rules** – edit `tools/event_analysis.py` RULES list.
* **ML Features** – modify `ml_anomaly.py` `row_to_features()` to include different behavioral signals.
* **ML Model** – replace `IsolationForest` with other anomaly detectors in `train_anomaly_model.py`.
* **DB seed** – run without seeding by default; set `SEED_DUMMY_LOGINS=1` if you want dummy rows (see `setups/create_logs_db.py`).
* **Thresholds / policy** – tweak the `SYSTEM_PROMPT` in `main.py`.
* **Additional tools** – just drop a new callable in `tools/` and add it to `TOOLS`.

### ML Configuration

| Environment Variable | Default | Purpose |
|---------------------|---------|---------|
| `ENABLE_ML_ANOMALY` | `0` | Set to `1` to enable ML pre-screening |
| `ANOMALY_MODEL_PATH` | `data/anomaly_model.joblib` | Path to trained model |
| `ANOMALY_THRESHOLD` | `0.0` | Score threshold for `ml_is_anomaly` flag |
| `RBA_TRAIN_CSV_PATH` | `rba-dataset-milrow.csv` | Training data path |
| `ANOMALY_SAMPLE_SIZE` | `200000` | Max rows to sample for training |
| `ANOMALY_CONTAMINATION` | `0.02` | Expected outlier rate (2%) |

## Limitations

* AbuseIPDB calls are live; heavy demos may hit free‑tier rate limits.
* DuckDuckGo search can also rate‑limit; the tool now fails gracefully.
* No persistence between runs except the SQLite file seeded on first launch.
* **ML model is unsupervised** – no labeled evaluation metrics provided (precision/recall would require ground truth labels and a held-out test set).

## Files Added for ML Feature

| File | Purpose |
|------|---------|
| `ml_anomaly.py` | Core ML module: feature extraction, training, inference |
| `train_anomaly_model.py` | Training script for the Isolation Forest model |
| `data/anomaly_model.joblib` | Saved model artifact (created after training) |


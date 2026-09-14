# SentinelAI — AI-Based Cybersecurity Log Monitoring & Threat Detection

## Ready-state architecture
Incoming KDD-format security logs → preprocessing → saved Random Forest pipeline → Normal/Attack classification → persistent alert store → SOC dashboard.

## Included
- `app.py` — Streamlit SOC dashboard and continuous log monitor
- `model.pkl` — trained preprocessing + Random Forest pipeline
- `train_model.py` — reproducible training script
- `logs/live_logs.csv` — live KDD-format log source
- `sentinelai_alerts.db` — created automatically at first run
- `test_logs.csv` — test data
- `dataset.csv` — training dataset
- `requirements.txt` — dependencies

## Run
```bash
python3 -m pip install -r requirements.txt
streamlit run app.py
```

## Continuous monitoring
Use **Live Log Monitoring**. The dashboard watches `logs/live_logs.csv` and refreshes every 2 seconds by default. Append new KDD-format records to that file; the AI engine will classify them and persist attack alerts in SQLite.

The project monitors structured security logs. It does not claim to capture raw network packets directly.

## Retraining
If the model must be retrained:
```bash
python3 train_model.py
```
This replaces `model.pkl` with a newly trained complete preprocessing + Random Forest pipeline.


## One-Click Launch

### Windows
Double-click `START_SENTINELAI.bat`.

The script checks for Python, installs the packages from `requirements.txt`, and starts the Streamlit dashboard.

### macOS
Double-click `START_SENTINELAI.command`.

If macOS blocks the script, open Terminal in this folder and run:
`chmod +x START_SENTINELAI.command`

Then double-click it again.

### Important
Python 3 must already be installed on the computer. The launcher installs the Python packages automatically, but it does not install Python itself.

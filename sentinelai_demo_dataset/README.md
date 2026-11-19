# SentinelAI synthetic demo logs

`synthetic_demo_logs.csv` contains 120 hand-crafted, synthetic KDD-style connection records: 60 `normal.` records and 60 labeled attack records. It is demonstration/testing data, **not a real benchmark dataset or real network capture**.

## Compatibility

The CSV has no header and has 42 columns: the 41 KDD input features expected by the existing SentinelAI `model.pkl`, followed by the optional `label` column. It was created from the feature list in the project's `app.py` and `train_model.py`; the model was not loaded, changed, or retrained.

Upload the CSV in **Log File Analysis**, or copy its rows into `logs/live_logs.csv` for the live-monitor demonstration. The supplied labels are ground-truth demo labels; model predictions may differ because they are generated examples rather than held-out benchmark observations.

Attack labels included: `neptune.`, `smurf.`, `portsweep.`, `satan.`, `back.`, and `guess_passwd.`.

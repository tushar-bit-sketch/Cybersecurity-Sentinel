# Cyber Sentinel — 3–5 minute operator demo

This walkthrough uses only generated fixtures. It demonstrates the real CLI scanner through the dashboard, evidence inspection, policy outcome, malformed-row recovery, and audit persistence. Run every command from the repository root in Windows PowerShell.

## Quick one-command demo

To run a standalone scan immediately:

```powershell
python -m sentinel scan --input data\demo.jsonl --format text --no-database
```

## 0. Prepare (once)

```powershell
python -m sentinel generate-data --seed 1729 --cases 12
python -m sentinel train --input data\training.jsonl --evaluation-input data\evaluation.jsonl --output models\sentinel-model.json
```

The second command prints held-out metrics from a **synthetic** evaluation fixture. Do not interpret them as field efficacy.

## 1. Start the dashboard and replay normal traffic

In terminal 1:

```powershell
python -m sentinel web --port 8765 --database data\demo-audit.sqlite3
```

Open <http://127.0.0.1:8765>. Choose **Normal** in the scenario selector, click **Scan**, and show the total/severity counters and risk trace. Select an event to inspect its class probabilities, model/anomaly values, risk components, feature evidence and record IDs.

## 2. Replay each threat class and inspect evidence

In the same dashboard, choose each scenario and click **Scan**:

1. **Port Scan** — inspect unique destination ports, destinations and connection rate.
2. **Brute Force** — inspect failed-auth count, failure ratio and account diversity.
3. **Lateral Movement** — inspect previously unseen internal peers and administrative-service connections.
4. **Data Exfiltration** — inspect outbound volume, transfer ratio and baseline-change evidence.

Point out that evidence contains measured values and contributing raw record IDs. A model label is an estimate, not proof. Optional additional scenarios are **Beaconing**, **Noise** (compare default tagging against the **Drop noise** control), and **Hostile** (malformed/unsupported records should be warned about while valid input continues).

## 3. Demonstrate malformed recovery and the risk gate

In terminal 2:

```powershell
python -m sentinel scan --input data\scenarios\hostile.jsonl --no-database
```

The scanner reports invalid rows to stderr and continues; a valid noise event remains processable. Then set an intentionally strict gate:

```powershell
python -m sentinel scan --input data\scenarios\dataexfiltration.jsonl --max-risk 0 --no-database
$gateCode = $LASTEXITCODE
"Expected breach exit 2; actual exit: $gateCode"
if ($gateCode -ne 2) { throw "Expected the strict max-risk policy to breach." }
```

`--max-risk` is strict `>`; equality is allowed. For a permissive threshold, a successful scan returns `0`.

## 4. Show persisted audit, then evaluation

The dashboard database includes alert details, run counters and triage history. Query the most recent runs and status counts:

```powershell
python -c "import sqlite3; c=sqlite3.connect(r'data\demo-audit.sqlite3'); print('Recent runs:', c.execute('SELECT input_source,valid_records,malformed_records,noise_records,dropped_noise_records,max_risk_score,policy_breach FROM telemetry_runs ORDER BY created_at DESC LIMIT 8').fetchall()); print('Alert statuses:', c.execute('SELECT status,COUNT(*) FROM alerts GROUP BY status').fetchall()); c.close()"
```

Back in the dashboard, mark one alert **REVIEWED** and show its status/history update. Finally, run the deterministic evaluation command:

```powershell
python -m sentinel evaluate --input data\evaluation.jsonl --model models\sentinel-model.json
```

The report lists accuracy, per-class precision/recall/F1, confusion matrix, false positives/negatives, and anomaly metrics. Both training and evaluation fixtures are synthetic and share generation rules; the metrics demonstrate reproducible execution, not real-world validation.

## Reset the demo audit database

Stop the dashboard with Ctrl+C. To reset only the demo database before a later run:

```powershell
Remove-Item data\demo-audit.sqlite3 -ErrorAction SilentlyContinue
```

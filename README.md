# NIDS-XAI: Network Intrusion Detection and Explainable AI

NIDS-XAI is a lab-oriented final-year project combining a Random Forest classifier, source-based detection rules, anomaly detection, explanations, a FastAPI backend, and a React dashboard. It supports CIC-IDS2017 and CIC-IDS2018 CSV data; UNSW-NB15 is not currently supported.

## Start the demonstration

Requirements: Python 3.11 or 3.12 recommended, Node.js 20.19+ or 22+, and npm. The full datasets require significant memory; the bundled samples are much smaller.

In one terminal:

```bash
cd nids_xai
python -m venv .venv
source .venv/bin/activate       # macOS/Linux; Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```bash
cd web
npm ci
npm run dev
```

Open the Vite address shown in the terminal (normally http://localhost:5173). If the frontend has already been built with `npm run build`, the backend also serves it at http://127.0.0.1:8000. On **Train**, select CIC-IDS2018 and **Bundled demonstration sample**, then start training. The sample contains several attack types and benign flows; its results represent this sample, not performance on the entire dataset. Training replaces the saved model and preprocessing files for the chosen dataset. Once training finishes, return to **Dashboard** and play the matching dataset. Select an alert to inspect explanations and submit feedback. Dataset samples do not contain source IPs, so those fields are shown as not recorded.

For full-data training, download the CIC-IDS CSVs from the [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) or [CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) site, put them under `nids_xai/data/raw/CIC-IDS-2017/` or `nids_xai/data/raw/CIC-IDS-2018/`, and select **Full dataset from data/raw**. Model files, processed data and feedback are local and are not included in Git. Older models without a matching preprocessing identity must be retrained.

## How it works

- Training first splits raw flows into training and holdout sets; feature selection and scaling are fitted on the training split. The binary classifier, a separate attack-type classifier, and an Isolation Forest fitted on benign training flows are saved locally.
- Dataset replay uses actual feature vectors but not real-time packet capture. It shows binary and attack-type predictions, anomaly indicators, SHAP/LIME explanations when available, a risk score, and the data source.
- Live capture groups IP packets into bidirectional flows. Per-source windows track contacted ports, connections to common authentication ports, and flow rates; TCP flag counts can trigger an additional heuristic. These are indicators, not proof of an attack. Capture requires Scapy, a suitable interface, and operating-system capture permissions; on Windows it also requires Npcap.
- The live flow extractor is **not yet validated against CICFlowMeter**. Live ML is disabled by default; unsupported features produce an unclassified event rather than a fabricated prediction. `NIDS_EXPERIMENTAL_LIVE_ML=1` opts into experimental live ML only when every selected feature is present. Even then the feature definitions and units must be independently validated before trusting its output.
- Risk is the larger of the rule severity and a weighted combination of model attack probability and rule severity. An anomaly-only alert is at least medium risk. These scores and thresholds are heuristic, not calibrated probabilities. An Isolation Forest anomaly means a flow differs from the benign training examples; it does not prove malicious intent.
- High/critical live alerts invoke prevention. The default `dry_run` records simulated actions; `monitor` logs only. `enforce` uses Linux `iptables` and must be used only inside an isolated lab. Dataset and remote sample replays cannot invoke enforcement. Blocks are temporary and released by the running service, but the in-memory block list is lost if the process exits unexpectedly; inspect and clean the `NIDS_BLOCK` chain in the lab if needed.
- Feedback is saved locally with the live feature vector and preprocessing identity where available. `python scripts/retrain.py --dataset 2018 --dry-run` checks for usable feedback; omit `--dry-run` to save a separate versioned model and report holdout metrics. Only compatible live samples are used; replay labels are excluded. Review the results before manually loading the model. This workflow does not automatically deploy a model.

The API has no authentication. Keep it on localhost or an isolated trusted lab network, especially when using firewall enforcement. `NIDS_ENFORCEMENT_MODE`, `NIDS_BLOCK_TTL`, and `NIDS_IP_WHITELIST` configure prevention. Whitelist all lab management and gateway addresses before experimenting.

## Verification

```bash
cd nids_xai
pip install -r requirements-dev.txt
python -m pytest -q
cd ../web
npm run build
npx vitest run
```

See [submission readiness](docs/SUBMISSION_READINESS.md) for the feature-by-feature status, evaluation caveats, and a demonstration checklist. A random flow-level holdout can contain related flows from the same capture; use a separate capture/time period or external dataset for a stronger generalization claim.

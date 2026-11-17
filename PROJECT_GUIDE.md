# NIDS-XAI: Complete beginner's project and running guide

This guide assumes you are new to cybersecurity, machine learning, and this project. Read the first four sections for a quick introduction, then use the later sections to prepare for a demonstration or viva.

> **The honest one-line description:** This is a lab-oriented network intrusion detection and prevention prototype that combines machine learning, traffic rules, anomaly detection, explanations, and a web dashboard. Its dataset demonstration works; live ML and real firewall enforcement still require further validation.

---

## 1. What problem are we solving?

Computers communicate by sending data over networks. Some communication is normal: opening a website, sending a message, or connecting to a server. Other communication can be suspicious: repeatedly probing many ports, making many rapid connection attempts, or overwhelming a service with traffic.

A network may generate too much traffic for a person to inspect manually. Our project helps by collecting or reading information about traffic and highlighting patterns that may need attention.

The intended workflow is:

```text
Network packets or a recorded dataset
                ↓
      Group traffic into flows
                ↓
      Extract/prepare features
                ↓
   Machine-learning model + rules
       + anomaly detection
                ↓
     Prediction and risk score
                ↓
     Explanation and dashboard
                ↓
  Simulated or lab-only prevention
```

There are two ways to try the project:

1. **Dataset demonstration:** The project plays back recorded, labeled traffic examples and sends them through the trained models. This is the recommended submission demo because it is repeatable and does not need packet-capture permissions.
2. **Live capture:** The project observes packets from a chosen network interface and applies traffic rules. Live ML predictions are disabled by default because the live feature extractor still needs to be checked against the tool used to create the training dataset.

A recorded dataset demo is a simulation of the monitoring workflow. It is not evidence that the system has blocked a real attacker or detected every kind of attack.

---

## 2. What do IDS, IPS, and NIDS mean?

- **Intrusion:** An attempt to access or misuse a system or network without authorization.
- **IDS — Intrusion Detection System:** Observes activity and raises an alert when it finds something suspicious. Think of it as an alarm.
- **IPS — Intrusion Prevention System:** Attempts to take action against suspicious activity, for example by blocking an IP address. Think of it as an alarm connected to a security gate.
- **NIDS — Network Intrusion Detection System:** An IDS that looks at network traffic rather than only files or activity inside one computer.
- **NIDS-XAI:** The name of this project. XAI stands for Explainable Artificial Intelligence.

Our project includes detection and a prevention component, but it is a **prototype for a controlled lab**, not a production-ready security product. Real firewall blocking has not been verified in an isolated Linux lab yet.

---

## 3. Basic networking terms

You do not need to memorize everything at once. Start with these ideas:

| Term | Simple meaning | Example |
| --- | --- | --- |
| **Network** | Connected devices that exchange data. | A laptop communicating with a web server. |
| **IP address** | A network address used to identify a device or endpoint. | `192.168.1.10` on a private network. |
| **Source IP** | The address that sent a packet or started an observed flow. | The laptop making a request. |
| **Destination IP** | The address receiving the traffic. | The server being contacted. |
| **Port** | A number that identifies a service or communication endpoint on a device. | Port 443 is commonly used for HTTPS. |
| **Packet** | A small unit of data sent through a network. | A piece of a web request or response. |
| **Protocol** | A set of rules devices use to communicate. | TCP and UDP. |
| **TCP** | A connection-oriented transport protocol that uses flags and other mechanisms to manage communication. | Often used for websites and SSH. |
| **UDP** | A transport protocol that sends datagrams without TCP's connection setup. | Often used for DNS or streaming. |
| **Flow** | A group of related packets summarized as one communication record. | Traffic between two IP/port endpoints using a protocol. |
| **Network interface** | A connection point through which a computer sends or receives traffic. | Wi-Fi, Ethernet, or a virtual interface. |
| **PCAP** | A file containing captured network packets. | A recording of packets from a lab network. |
| **Firewall** | Software or hardware that controls which traffic is allowed or blocked. | Linux `iptables`. |

**Packet versus flow:** A packet is one piece of traffic. A flow is a summary of related packets. A flow might describe how long communication lasted, how many packets were sent, their sizes, and timing. ML models in this project work with flow features.

**What are TCP flags?** TCP packets can contain flags such as SYN and ACK. They are signals used during communication. For example, SYN is commonly used when starting a connection. A rule can look for an unusual number of SYNs compared with ACKs, but this alone does not prove an attack.

---

## 4. Attacks the project discusses

### Port scan

A port scan contacts many ports to discover which services might be available. A scanner may be malicious, but an authorized administrator can also scan a system. Our rule looks for many distinct destination ports from one source during a time window.

### Brute-force-like behavior

A brute-force attack tries many passwords or credentials. Our network rule observes a high number of connections to common authentication ports such as SSH, FTP, or RDP. **It cannot see whether those login attempts actually failed**, so it reports a suspicious pattern rather than proof of password guessing.

### DoS and DDoS

- **DoS — Denial of Service:** An attempt to make a service unavailable, often by overwhelming it or exhausting its resources.
- **DDoS — Distributed Denial of Service:** A similar attack involving traffic from multiple sources.

The rule engine looks for a high rate of completed flows from one source. That is a DoS-like indicator, not a complete distributed attack detector. Normal busy traffic can also trigger rate-based rules.

### SYN flood-like behavior

A SYN flood is associated with an unusually high volume of connection-start requests. A rule compares SYN and ACK counts. This is a heuristic; an unusual ratio alone is not conclusive.

**Important:** This project highlights possible attacks. A high score, rule match, or anomaly is not proof that a person or IP address is malicious.

---

## 5. Moving the project to another laptop

### What to copy

Copy or clone the **whole project source folder**, including at least:

```text
Project folder/
├── PROJECT_GUIDE.md                 ← this guide
├── README.md
├── nids_xai/
│   ├── api/
│   ├── config/
│   ├── rules/
│   ├── src/
│   ├── tools/
│   ├── examples/test_csvs/         ← bundled demo CSVs
│   ├── requirements.txt
│   └── requirements-dev.txt
└── web/
    ├── src/
    ├── package.json
    └── package-lock.json
```

Before leaving your current laptop, make sure the changes you want to transfer are actually included in the copy. If you use Git, uncommitted changes are not transferred by simply cloning the repository; commit or otherwise copy the current files first.

The following are usually excluded from Git and can be recreated on the new laptop:

- `nids_xai/.venv/` — Python environment.
- `web/node_modules/` — JavaScript packages.
- `web/dist/` — built website.
- `nids_xai/models/` — trained models and their metadata.
- `nids_xai/data/processed/` — prepared data.
- `nids_xai/data/raw/` — full downloaded datasets.

**Do not copy a virtual environment from one laptop to another.** Create it again on the new laptop. You can train the bundled sample again; full dataset downloads are optional for the first demo. If you do want to transfer already-trained models, also transfer the matching processed data and preprocessing files, but retraining on the new laptop is generally simpler. The bundled CSV samples under `nids_xai/examples/test_csvs/` must be present.

### Install these tools

1. **Python:** Python 3.11 or 3.12 is recommended. Install it from the official Python website. On Windows, select the option to add Python to PATH if the installer offers it.
2. **Node.js:** Use a version compatible with the project: Node.js 20.19 or newer, or a current Node.js 22 release. npm comes with Node.js.
3. **A browser:** Chrome, Edge, Firefox, or another modern browser.
4. **Optional editor:** Visual Studio Code makes it easy to open the folder and use its terminal, but it is not required.
5. **Internet connection for setup:** Needed to install the Python and JavaScript packages. It is not required to download the full CIC datasets for the bundled-sample demo.

Check the installations in a terminal:

```text
python --version
node --version
npm --version
```

On macOS/Linux the Python command may be `python3`. On Windows the Python launcher may be `py`. If a command is not recognized, install the tool or reopen the terminal after installation.

### What is a terminal?

A terminal is a window where you type commands. On Windows, use PowerShell or the terminal in VS Code. On macOS, open Terminal. On Linux, open your terminal application.

`cd` means **change directory**. You must run each command from the folder described below. If the path contains spaces, put it in quotes. For example:

```text
cd "path to the project folder"
```

Open **two terminal windows or tabs**: one for the Python backend and another for the React frontend. Keep both open while using the dashboard.

---

## 6. First-time setup on Windows

These commands use **PowerShell**. Open PowerShell in the project folder—the folder containing both `nids_xai` and `web`.

### Terminal 1: set up and start the backend

```powershell
cd nids_xai
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

If you installed Python 3.12 instead, replace `py -3.11` with `py -3.12`. If the `py` launcher is unavailable but `python --version` shows the intended Python, use `python -m venv .venv`.

Wait until the server reports that it is running. Leave this terminal open. The backend address is `http://127.0.0.1:8000`.

These commands call the virtual environment's Python directly, so you do not need to change PowerShell's execution policy or activate the environment.

### Terminal 2: set up and start the frontend

Open a **new** PowerShell terminal in the project folder:

```powershell
cd web
npm ci
npm run dev
```

Open the local address displayed by Vite, usually `http://localhost:5173`, in your browser. If Vite chooses another port, use the address it prints.

**Next time:** The environment and packages are already installed. In Terminal 1, go to `nids_xai` and run the last `python.exe -m uvicorn ...` command. In Terminal 2, go to `web` and run `npm run dev`. You only need to reinstall when dependencies change or the environment is missing.

---

## 7. First-time setup on macOS or Linux

Open a terminal in the project folder, containing `nids_xai` and `web`.

### Terminal 1: set up and start the backend

```bash
cd nids_xai
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Use `python3.11` or `python3.12` instead of `python3` for the virtual-environment command if the default Python version is unsuitable. Leave the backend terminal running.

### Terminal 2: set up and start the frontend

Open a **new** terminal in the project folder:

```bash
cd web
npm ci
npm run dev
```

Open the address printed by Vite, usually `http://localhost:5173`.

**Next time:** Start the backend with `.venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8000` from `nids_xai`, and start the frontend with `npm run dev` from `web`.

### Stopping the project

In each terminal, press **Ctrl+C**. Closing the terminal also stops the process. The backend and frontend are separate, so stop both when you are finished.

### Optional: serve a built dashboard from the backend

From `web`, run `npm run build` once. When the backend is running, it can serve that built dashboard at `http://127.0.0.1:8000`. Rebuild after frontend code changes. The normal two-terminal development setup above is easier to understand when starting out.

---

## 8. Your first project demonstration

This is the recommended path on a new laptop. It uses included sample data and does **not** need a network attack or a full dataset download.

1. Start the backend and frontend using the instructions above.
2. Open the dashboard in the browser.
3. Click **Train** in the top navigation.
4. Select **CIC-IDS 2018**.
5. Under **Training data**, select **Bundled demonstration sample**.
6. Click **Start Training**. Wait until the progress reaches 100% and the results appear. Do not close the backend or frontend terminals.
7. Return to **Dashboard**. Check that **Model** and **Traffic** are both set to **2018**.
8. Click **Play Dataset**. Recorded flows will appear in the alert log. The playback contains both attack and benign examples; its selection is designed for a demo and is not a measurement of real-world traffic proportions.
9. Select an alert row. Inspect its risk, prediction, and available explanation. Attack rows may show a predicted attack type. For more details, try the **XAI** page.
10. Open **Evaluate** and click **Run Evaluation** to see holdout metrics and the confusion matrix.
11. Leave prevention in the default **DRY_RUN** mode. During dataset replay the project must not block real IP addresses.

**Why are IPs shown as “Not recorded”?** The bundled sample used for this demo does not include source/destination IP information in the replayed feature records. The project does not invent addresses for those rows.

**Why might a 2017 demo not show a specific attack type?** The bundled 2017 sample contains benign and port-scan examples, so it may not have enough different attack classes for the separate attack-type model. The 2018 sample is better for showing several categories.

**Important:** Training a dataset replaces the saved model and preprocessing files for that dataset on that laptop. The bundled sample is small; its accuracy cannot be used as proof of full-dataset or production performance.

---

## 9. What each screen does

- **Dashboard:** Shows the monitoring controls, traffic graphs, alert log, risk levels, predictions, available explanations, suspicious IPs when recorded, and prevention actions. Dataset replay does not contain real IPs.
- **Alerts:** Provides a list of stored recent events and filtering. The backend keeps a limited in-memory buffer, currently up to 500 events; the live dashboard itself shows a smaller recent set.
- **XAI:** Lets you explore a sample prediction and its SHAP/LIME explanations when the trained model and explanation dependencies are available.
- **Train:** Select a dataset and either the bundled sample or the full local dataset, then train the models.
- **Evaluate:** Shows performance on the holdout data and, when available, evaluation charts such as the confusion matrix, ROC, and precision–recall curves.
- **Classify:** Accepts compatible flow-feature CSV data and returns predictions. Its columns must match the model's expected feature definitions sufficiently well.
- **Settings:** Shows the active model and lets you select an available saved model. Stop monitoring before switching models or starting training.

The exact appearance may vary with the browser size. The backend API can also be inspected at `http://127.0.0.1:8000/docs` while the backend is running. That page is automatically generated by FastAPI.

---

## 10. What does the project contain?

| Part | Technology | Job |
| --- | --- | --- |
| Frontend | React, Vite, JavaScript | Displays controls, charts, alerts, metrics, and explanations in the browser. |
| Backend | Python, FastAPI | Receives requests, manages models and monitoring, and sends results to the browser. |
| Real-time updates | WebSockets | Keep a connection open so alerts and statistics can be sent to the dashboard as they occur. |
| ML | scikit-learn Random Forest | Predicts benign versus attack and, using a separate model when available, an attack category. |
| Anomaly model | scikit-learn Isolation Forest | Flags flows that differ from the benign examples it learned from. |
| Rule engine | Python and YAML | Checks configured thresholds such as many destination ports or unusually high flow rates. |
| Explainability | SHAP and LIME | Help describe which features influenced a model's prediction. |
| Capture | Scapy and a flow accumulator | Read supported live IP packets and group them into flows. |
| Prevention | Python service and optionally Linux `iptables` | Logs, simulates, or attempts lab-only blocking of an IP. |
| Storage | Local files and an in-memory alert buffer | Saves models, processed data, and feedback; recent dashboard events are held in memory. |

The backend is **Python**, not Go. The original project idea mentioned Go as a possible backend skill, but the implemented backend uses FastAPI and Python.

### Where to find the code

- `nids_xai/api/main.py`: starts the FastAPI application and connects its routes.
- `nids_xai/api/routers/`: API endpoints for training, monitoring, evaluation, alerts, and other actions.
- `nids_xai/api/services/`: backend services for monitoring, models, alerts, explanations, anomaly detection, and prevention.
- `nids_xai/src/preprocessor.py`: cleans, selects, and scales features.
- `nids_xai/src/training_data.py`: creates the train/holdout split before fitting preprocessing.
- `nids_xai/src/model_trainer.py`: trains and saves the binary model.
- `nids_xai/src/type_trainer.py`: trains the separate attack-type classifier.
- `nids_xai/src/anomaly.py`: trains and scores the anomaly model.
- `nids_xai/src/monitor.py` and `nids_xai/tools/pcap_to_csv.py`: packet capture and basic flow accumulation.
- `nids_xai/rules/rules.yaml` and `nids_xai/rules/engine.py`: rule thresholds and their evaluation.
- `nids_xai/rules/risk_score.py`: risk calculation.
- `nids_xai/scripts/retrain.py`: creates a separate feedback-based model candidate.
- `web/src/pages/` and `web/src/components/`: the React pages and dashboard pieces.
- `nids_xai/tests/`, `nids_xai/api/tests/`, and frontend test folders: automated checks.

---

## 11. Datasets and features

### What is a dataset?

A dataset is a collection of examples. Here, each row generally represents a flow and its columns contain measurements or a label. The label tells us whether the flow is benign or which recorded attack category it belongs to.

This project supports CIC-IDS2017 and CIC-IDS2018. Full datasets can be obtained from the Canadian Institute for Cybersecurity:

- [CIC-IDS2017 official page](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CIC-IDS2018 official page](https://www.unb.ca/cic/datasets/ids-2018.html)

Place full CSVs under `nids_xai/data/raw/CIC-IDS-2017/` or `nids_xai/data/raw/CIC-IDS-2018/` and select the full-data option in Train. The loader expects the dataset files it recognizes; consult the project configuration if downloaded names differ. Full datasets are large and can need substantial RAM and time.

**UNSW-NB15:** It was mentioned as a possible dataset in the initial idea, but it is not currently implemented. Do not say this version supports it.

### What is a feature?

A feature is a measurable input to a model. Examples include:

- Destination port.
- Flow duration.
- Number of forward and backward packets.
- Packet lengths and rates.
- Time between packets.
- TCP flag counts.

The exact features used depend on training and selection. A model needs incoming features that have the same meaning and units as its training features; matching names alone is not enough.

### Why preprocess data?

Raw datasets can contain invalid values, unnecessary identifiers, very different numerical scales, or many columns. The preprocessing pipeline cleans values, removes unsuitable columns, selects useful features when configured, and scales them for the model. The preprocessing configuration is saved with an identity check so a model is not silently paired with a different preprocessing pipeline.

---

## 12. Machine learning in simple language

### Training versus prediction

- **Training:** Give a model examples and labels so it can learn patterns.
- **Prediction/inference:** Give the trained model a new feature row and ask what it predicts.

### Why split the dataset?

The project splits raw data into approximately **80% training** and **20% holdout**. The model and data-dependent preprocessing are fitted using the training portion. The holdout is kept for evaluation.

A good score on the holdout is useful, but a random row split may still place related flows from the same capture in both parts. For stronger evidence of real-world performance, test on a separate capture, time period, or external dataset and document the conditions.

### Random Forest

A Random Forest is a collection of decision trees. Each tree makes a prediction based on feature values; the forest combines the trees' outputs. This project uses:

1. A **binary model**: benign or attack.
2. A **separate attack-type model**, when enough attack types are available: for example, a predicted DoS or brute-force category.

The category shown by the model is a prediction. A dataset's original label is ground truth provided by the dataset; the two are not the same thing.

### Model confidence

The dashboard can display the model's confidence in its decision. For example, a displayed 90% attack score is the model's output for that input. It does **not** guarantee that nine out of ten such cases will be real attacks; that interpretation would require calibration and validation.

### Isolation Forest and anomaly detection

The Isolation Forest is trained using benign training flows. It looks for inputs that are unusual relative to those examples. A flow can be unusual and still be harmless, so an anomaly is a warning for investigation, not proof of an attack. An anomaly-only alert does not automatically enforce a firewall block.

---

## 13. Rule engine and risk scoring

A **rule** is an explicit condition chosen by a developer, such as “more than a certain number of destination ports from one source.” Unlike ML, it does not learn that condition automatically.

Examples of the current default rules in `nids_xai/rules/rules.yaml`:

| Rule | Default idea | What it can indicate |
| --- | --- | --- |
| Port scan | At least 50 distinct destination ports from one source in a 60-second window. | Possible scanning. |
| Authentication-port burst | At least 20 connections to ports 21, 22, or 3389 in a 60-second window. | Possible brute-force-like activity; failed logins are not verified. |
| High flow rate | At least 50 completed flows per second, measured over a 10-second window. | Possible DoS-like behavior. |
| SYN/ACK ratio | At least 10 SYN flags with a SYN-to-ACK ratio of at least 5. | Possible SYN flood-like activity. |

The source windows use **completed flow events**. Events can be processed in batches when flows expire, which can affect the observed rate. These values are defaults for a prototype and must be tuned and validated for the network being observed. A rule can raise an alert even if the binary model did not.

### How is the risk score calculated?

The risk score is a **heuristic from 0 to 100**, not a measured probability of harm. The project takes the larger of:

1. The matched rule's severity score, and
2. A weighted combination: **70% model attack probability + 30% rule score**.

The result is converted to 0–100. An anomaly-only alert is given at least medium risk. Default levels are:

| Score | Level |
| --- | --- |
| 0–39 | Low |
| 40–69 | Medium |
| 70–89 | High |
| 90–100 | Critical |

For example, with model attack probability 0.8 and rule score 0.75, the weighted combination is `0.7 × 0.8 + 0.3 × 0.75 = 0.785`, giving a score around 78. Because that is above the rule score of 75, the result is high risk. Thresholds and weights are engineering choices, not universally correct values.

---

## 14. Explainable AI: SHAP and LIME

A plain classifier might say “attack” without helping a person understand the decision. **Explainable AI**, or XAI, provides information about factors that influenced a prediction.

- **SHAP:** Estimates how features contribute to a particular model output. The project displays feature contributions that push a prediction toward attack or benign.
- **LIME:** Creates a local, simpler explanation around one input by studying nearby variations and the model's responses.
- **Rule explanation:** Shows the condition that matched, such as a high number of destination ports. This is separate from SHAP or LIME.

An explanation is about the **model or rule's reasoning**, not an independently proven cause. SHAP and LIME may disagree because they use different methods. Numerical runtime warnings were observed from LIME dependencies during local testing, although explanations were returned; review them in the final environment.

If an alert has no model-compatible feature vector or an explainer cannot be initialized, a model explanation may be unavailable. The rule reason can still be useful.

---

## 15. Prevention modes and feedback

### Prevention

The prevention service has three modes:

| Mode | Meaning |
| --- | --- |
| `monitor` | Logs what would be considered; no real firewall block. |
| `dry_run` | The default. Records a simulated block; no real firewall block. |
| `enforce` | Attempts to use Linux `iptables` for a real block. Only for an isolated lab. |

For eligible **live** high/critical alerts, the service can invoke the selected action for the source IP. Dataset replay and remote dataset feeds do not trigger real enforcement. A whitelist prevents configured addresses from being blocked. The default block duration is one hour, and the running service attempts to remove expired blocks.

**Do not enable `enforce` on your own laptop, a college network, or any shared/production network.** This project has not been verified as a real firewall controller in an isolated Linux lab. Its block list is in memory; if the process stops unexpectedly, a firewall rule could remain and may require manual lab cleanup. The API has no authentication, so keep it on localhost or a trusted isolated lab network.

### Human feedback

An analyst can mark an alert as **true positive** or **false positive**:

- **True positive:** The analyst confirms the attack alert was correct.
- **False positive:** The alert was raised for traffic the analyst has determined was benign.

Feedback is saved locally. The retraining script uses only compatible live feature vectors with a matching preprocessing identity; replay feedback is excluded from training. It trains a separate candidate, evaluates it on the saved holdout, and requires review before the candidate is manually loaded. It does not automatically replace the active model. Real, reviewed live data is still needed to validate this loop end to end.

To inspect whether compatible feedback exists, from `nids_xai` using the virtual environment's Python:

```text
python scripts/retrain.py --dataset 2018 --dry-run
```

Use `.\.venv\Scripts\python.exe` in PowerShell or `.venv/bin/python` on macOS/Linux in place of `python` if the environment is not activated. A message saying there is no compatible live feedback is expected if you have only used dataset replay.

---

## 16. How do we know whether the model is good?

A **confusion matrix** compares actual labels with model predictions:

| | Predicted attack | Predicted benign |
| --- | --- | --- |
| **Actually attack** | True positive (TP): attack caught | False negative (FN): attack missed |
| **Actually benign** | False positive (FP): false alarm | True negative (TN): benign correctly recognized |

Important metrics:

- **Accuracy:** `(TP + TN) / all cases`. Overall correctness; can be misleading when one class is much more common.
- **Precision:** `TP / (TP + FP)`. Of alerts predicted as attacks, how many were actually attacks? Higher precision generally means fewer false alarms.
- **Recall:** `TP / (TP + FN)`. Of actual attacks, how many were caught? Higher recall generally means fewer missed attacks.
- **F1 score:** Combines precision and recall into one measure. It is useful when you care about both.
- **False-positive rate:** `FP / (FP + TN)`. Fraction of actually benign examples incorrectly flagged as attacks.
- **ROC-AUC:** Measures how well the model ranks attack examples above benign examples over decision thresholds. It is not the same as accuracy.

**Example:** If 100 real attacks exist and the system detects 90, recall is 90%. If it raises 100 attack alerts and 90 are real attacks, precision is 90%. These are illustrative numbers, not a claim about this project.

During an earlier local run, the bundled 2018 sample produced 96.71% accuracy on a 1,123-row holdout. Your number may differ with training mode or software versions. This is a **sample-specific result**, not a validated accuracy for all network traffic. Always show precision, recall, false positives, and the test setup alongside accuracy.

---

## 17. Limitations and future work

Be ready to state these clearly if asked:

1. **Live ML is not validated.** The basic live packet extractor is not yet verified to reproduce CICFlowMeter features and units. Live ML is disabled by default; unsupported feature sets are left unclassified.
2. **The firewall path needs lab validation.** Real `iptables` enforcement and cleanup have not been tested end to end in an isolated Linux environment. Default mode is simulated.
3. **Heuristics can be wrong.** High traffic or many connections may be legitimate; connection counts do not prove failed authentication.
4. **Dataset replay is not real capture.** It uses recorded feature rows; the bundled replay does not have source/destination IPs.
5. **Anomalies are not automatically attacks.** They indicate deviation from the benign training examples.
6. **Evaluation is limited.** A random flow split can contain related traffic in both partitions. A separate capture or period is needed for a stronger generalization test.
7. **Feedback retraining needs real evidence.** The mechanism exists, but a validated live feedback dataset is needed to test the full workflow meaningfully.
8. **Coverage is incomplete.** UNSW-NB15 and production-grade distributed attack detection are not implemented.
9. **The API is unauthenticated.** It must remain on localhost or in a trusted isolated lab. This is not a hardened production deployment.
10. **Dependency and explanation caveats.** The last local audit reported six high-severity findings in development tooling, while the production dependency audit reported none. LIME emitted some numerical warnings during testing.
11. **Existing report and slides may be stale.** Check them against the code and this guide before submitting, especially any accuracy or live-prevention claims.

Useful next steps include validating the live extractor against reference CICFlowMeter captures; testing real firewall actions and recovery in a disposable isolated Linux lab; evaluating on new traffic; improving authentication and deployment security; and collecting reviewed feedback.

---

## 18. Common questions and simple answers for your viva

**1. What is the aim of your project?**

To identify potentially suspicious network traffic using ML, rules, and anomaly detection, explain the result, and demonstrate controlled prevention through a dashboard.

**2. What is the difference between IDS and IPS?**

An IDS detects and alerts. An IPS attempts to prevent or stop suspicious activity. Our prototype includes detection and a lab-oriented prevention service.

**3. Why combine ML and rules?**

Rules provide clear, specific conditions; ML can learn patterns from labeled examples. Combining them can highlight different kinds of suspicious traffic, but neither is guaranteed to be correct.

**4. Which ML model do you use?**

A Random Forest for binary detection and a separate Random Forest for attack type when the training data supports it. An Isolation Forest is used for anomaly detection.

**5. Why Random Forest?**

It works with tabular features, models non-linear relationships, and provides feature importance. It is a practical baseline; this does not prove it is the best model for every network.

**6. What is the difference between binary detection and attack classification?**

Binary detection asks benign or attack. The separate type classifier asks which attack category an attack resembles.

**7. What is anomaly detection?**

Finding examples that differ from the benign training patterns. An anomaly can be legitimate and needs investigation.

**8. What is explainable AI?**

Methods that help people understand factors influencing a model's output. We use SHAP and LIME, plus plain rule reasons.

**9. Do explanations prove why an attack occurred?**

No. They describe the influence of features on the model or which rule matched; they are not proof of a real-world cause.

**10. How is risk different from model confidence?**

Confidence is a model output. Risk combines model output and rule severity using project-defined weights, with an additional minimum for anomaly-only alerts. It is a heuristic, not a calibrated probability.

**11. What is a false positive?**

Benign traffic incorrectly flagged as an attack. It wastes investigation time and can cause disruption if blocking is enabled.

**12. What is a false negative?**

An actual attack incorrectly classified as benign or not detected. It can allow malicious activity to go unnoticed.

**13. Why are precision and recall important?**

Precision helps describe false alarms among alerts; recall helps describe missed attacks among actual attacks. Accuracy alone can hide these problems.

**14. What data do you train on?**

The implementation supports CIC-IDS2017 and CIC-IDS2018. For a quick demo it includes smaller samples; UNSW-NB15 is not currently supported.

**15. What is the train/test split?**

About 80% of raw rows are used to fit preprocessing and train, and 20% are kept as a holdout for evaluation. A separate capture would make a stronger test.

**16. What is a feature?**

A measurable input, such as packet rate, flow duration, or a TCP flag count.

**17. What is the difference between a packet and a flow?**

A packet is one unit of communication. A flow summarizes related packets between endpoints over time.

**18. How do you detect a port scan?**

One rule checks whether a source has contacted many distinct destination ports in a window. It is a suspicious pattern, not proof of malicious intent.

**19. Can your brute-force rule confirm an incorrect password?**

No. It counts network connections to selected authentication ports; it does not verify login failures.

**20. How does prevention work?**

The prevention service can log, simulate, or attempt Linux firewall blocking. The default is dry-run. Real enforcement is intended only for an isolated lab and still needs validation.

**21. Does the replay block the IPs it shows?**

No. The bundled replay does not contain real IPs, and dataset/remote replay cannot trigger real enforcement.

**22. Can you claim this is a production-ready IDS/IPS?**

No. It is a lab prototype. Live feature parity, firewall behavior, evaluation, and security hardening need further work.

**23. Why is live ML disabled by default?**

The live extractor has not yet been validated to produce the same feature meanings and units as the dataset generation tool. A confident model output on mismatched data would be misleading.

**24. What happens when the input features do not match?**

The live flow can be marked unclassified instead of producing a fabricated ML prediction. Rules can still produce alerts when their required observations are available.

**25. How does human feedback help?**

An analyst labels an alert. Compatible live feature vectors can be used to train a separate candidate, which is evaluated and reviewed before manual loading. Replay feedback is not used for training.

**26. What technologies did you use?**

Python/FastAPI, scikit-learn, SHAP, LIME, Scapy, React, Vite, WebSockets, YAML, and optionally Linux `iptables` in an isolated lab.

**27. Why use WebSockets?**

They keep a connection open so the backend can push new alerts and statistics to the dashboard without the browser repeatedly requesting each update.

**28. Is this backend written in Go?**

No. The original idea considered Go as a possible skill, but the implemented backend is Python with FastAPI.

**29. Why can't you use the sample accuracy as a real-world guarantee?**

The sample is small and drawn from a specific recorded dataset. A random flow split can also contain related traffic in both sets. New networks may behave differently.

**30. What is your main contribution?**

The project integrates data preparation, ML predictions, rules, anomaly detection, explanations, a dashboard, and a controlled prevention workflow in one prototype. The contribution should be presented alongside its limits.

---

## 19. A short presentation script

Adapt this to your own words:

> “Our project is an AI-assisted network intrusion detection and prevention prototype. It analyzes flow features from CIC-IDS traffic using a Random Forest classifier, a rule engine, and an Isolation Forest for anomalies. The dashboard shows predictions, risk, and explanations using SHAP, LIME, and rule reasons. We split the data before fitting preprocessing and evaluate on a holdout. For the demo, we replay recorded dataset flows and use simulated prevention. Live rules are available, while live ML and real firewall enforcement require further validation in an isolated lab.”

A useful demo order is: **Train → Dashboard replay → select an alert → XAI → Evaluate**. Explain that the data is recorded and that sample metrics do not establish real-world performance.

---

## 20. Troubleshooting

| Problem | What to check |
| --- | --- |
| `python`, `py`, `node`, or `npm` not recognized | Install the required tool from its official source and reopen the terminal. Use the appropriate Python command for your OS. |
| `No module named ...` | Ensure you created the virtual environment and installed `requirements.txt` using that environment's Python. Run the backend using that same Python. |
| `npm ci` fails because no package file is found | You may be in the wrong folder. Run it inside `web`, where `package.json` and `package-lock.json` exist. |
| Browser cannot connect | Keep both terminals running. Check the backend is on port 8000 and open the address Vite printed. Look for errors in the terminal. |
| Port 8000 or 5173 is already in use | Stop the other process using the port or follow the address printed by the server. If you change backend ports, the development proxy may also need to be updated. |
| `No model loaded` or no processed data | Open **Train**, choose the bundled 2018 sample, and wait for training to finish. Models are not normally included when cloning Git. |
| Training says no raw CSVs found | You chose the full dataset option without installing the full files. Select the bundled sample for the first demo or place the full dataset in the documented folder. |
| Model and preprocessing do not match | Train the selected dataset again. Older model artifacts without the matching preprocessing identity are not accepted. |
| Replay says the selected model was not found | Select the dataset/model you actually trained—typically 2018 for the first demo. |
| Source IP is `Not recorded` | Expected for bundled dataset replay. Do not describe invented IPs as real. |
| No attack-type prediction | The type model might not have been trained, may lack enough distinct attack classes, or may not match the active preprocessing. The 2018 bundled sample is the better demo choice. |
| No explanation | Check that the selected event has model features and the model/explanation packages are available. An unclassified live flow cannot have a normal ML explanation. |
| Live capture does not start | It may require OS capture permissions, a suitable interface, and Scapy; Windows requires Npcap. Use dataset replay for the basic submission demo. |
| No real IP is blocked | Expected in `dry_run` and during replay. Do not switch to enforce mode on a regular or shared machine. |
| Feedback retraining reports no compatible live samples | Expected if you only labeled dataset replay or live flows without usable model features. |
| Training or SHAP/LIME is slow | Wait for the backend; larger datasets need more RAM and time. The bundled sample is intended for a faster demo. |

---

## 21. Tests and final checklist

To run automated backend tests, install the development requirements in the same Python environment, then run `python -m pytest -q` from `nids_xai`. To check the frontend, run `npm run lint`, `npx vitest run`, and `npm run build` from `web`.

On a fresh machine without a trained model, a model-dependent test may be skipped until you train one. Passing tests supports confidence in the tested paths; it does not prove a real network deployment is safe or complete.

Before submission:

- [ ] Confirm the new laptop has the complete current source and bundled sample CSVs.
- [ ] Install dependencies and train the bundled 2018 sample on that laptop.
- [ ] Practice the dataset replay, alert explanation, and evaluation screens.
- [ ] Keep prevention in `dry_run` for the presentation.
- [ ] Explain that replay is recorded data and that live ML and real enforcement require further validation.
- [ ] State the sample, split, and limitations whenever presenting metrics.
- [ ] Check the report and slides for claims that no longer match the implementation.
- [ ] Keep the backend and frontend terminals open during the demo.

For a compact implementation checklist, see `docs/SUBMISSION_READINESS.md`; for a shorter technical overview, see `README.md`.

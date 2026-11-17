# Submission readiness and demonstration notes

## Feature coverage

| Idea | Current implementation and limits |
| --- | --- |
| Dataset to model | CIC-IDS2017/2018 training, including explicitly selected bundled samples. UNSW-NB15 is not supported. |
| Binary ML and attack type | Random Forest binary model and a separate attack-type model. The type model is available only when the sample contains sufficient distinct attack classes and its preprocessing matches. |
| Live traffic | Scapy captures IPv4 TCP/UDP flows and rules evaluate source windows. Live ML is disabled by default because the local feature extractor has not been validated against CICFlowMeter. Some CIC-IDS model features are unsupported; those flows stay unclassified. |
| Rules and risk | Port scan, authentication-port connection bursts, high flow rate and SYN/ACK heuristics. A rule can raise an alert independently of the classifier. Risk is heuristic and should not be described as a probability. |
| Anomaly detection | Isolation Forest trained on benign training flows. An anomaly indicates deviation from the training sample, not a confirmed attack. |
| Explanation | Rule reasons and SHAP/LIME model explanations when models and compatible data are available. Model explanations describe influence on the model, not proof of causation. |
| Prevention | Monitor, simulated and iptables modes. Automatic actions use live alerts with high/critical risk; replay does not enforce. Firewall enforcement and expiry require an isolated Linux lab and remain unverified on this machine. |
| Dashboard | Flow charts, alerts, risk, type predictions, confidence, explanations, feedback and prevention actions. Dataset replay has no real IPs. Counts cover the latest 500 events. |
| Feedback | Review labels are stored. Retraining uses compatible live vectors, excludes replay data, preserves the holdout and saves a separate model for review. This flow requires real labeled live observations to validate end to end. |

## Demonstration checklist

1. Start the backend and frontend as shown in the root README. Keep prevention in its default `dry_run` mode.
2. Train the **CIC-IDS2018 bundled demonstration sample** from the Train page. Observe that source and holdout metrics are labeled as sample results.
3. On Dashboard, play the 2018 dataset. Point out the prediction, predicted attack category, confidence, risk and explanation. IP addresses are unavailable because they are not in this sample.
4. Open Evaluate to show the independent holdout confusion matrix, precision, recall and F1. A random flow-level split is not a realistic deployment benchmark: related flows may appear in both partitions. Evaluate on a distinct capture/time period for a stronger result.
5. If an isolated Linux lab and capture permissions are available, use live rule monitoring with dry-run prevention. Describe rules as heuristics and live ML as experimental until extractor feature parity is validated.

Do not claim that every attack is detected, that a model probability is calibrated, or that the bundled sample's metrics generalize to production traffic. The API is unauthenticated and should remain on localhost or an isolated trusted network. Firewall state is held in memory; an interrupted process may leave a Linux rule behind.

Source windows use completed flow events, so batching at flow expiry can affect measured rates. Authentication-port connection counts do not establish failed logins. The development dependency audit currently reports six high-severity findings in Vite/Vitest tooling; the production dependency audit reports none.

In local testing, LIME produced explanations but some numerical runtime warnings were emitted by its dependencies. Review explanation outputs and validate them with the final environment before presenting them as reliable. Existing report and presentation files predate this review and should be checked for outdated claims.

# SENTINELFORGE — AI-Powered Threat Detection & Security Analytics Platform

SENTINELFORGE is a defensive cybersecurity Security Operations Center (SOC) research prototype built as a fourth-year engineering project. It ingests multi-format security logs (`CSV`, `JSON`, `TXT` syslog), extracts behavioral and statistical features, detects threats using a transparent hybrid engine (**Deterministic Rules + Isolation Forest + Supervised Logistic Regression**), maps alerts to **MITRE ATT&CK**, correlates multi-stage attack sequences, tracks **Digital Forensics** evidence chains, enforces **Role-Based Access Control (Analyst vs. Administrator)** with immutable **Audit Logging**, and evaluates ML models using strict **Train/Test separation**.

> **Academic & Defensive Notice**: SENTINELFORGE is strictly a defensive log-analysis and research platform. All pre-loaded events and offline threat intelligence records are synthetic demonstration data labeled clearly in the UI. Demonstration authentication is provided for local RBAC simulation and is not intended for production identity management.

---

## Core Capabilities

1. **Security Dashboard**: Real-time SOC overview showing total events analyzed, open/acknowledged/resolved threat counts, severity distribution, hourly event vs. threat trend charts, attack categories, top suspicious IPs, and recent audit activity.
2. **Log Analyzer & Dataset Management**:
   - Drag-and-drop or browse `.csv`, `.json`, and `.txt` (syslog/sshd) files.
   - Row-level validation reporting malformed IPs, timestamps, or schemas gracefully.
   - One-click loading of bundled sample security log datasets (`samples/`).
   - Searchable event table with feature inspection.
3. **Hybrid Threat Detection Engine**:
   - **Rule-Based Signatures**: Brute-force bursts, repeated failed logins, multi-port scanning, privilege escalation commands, malware payload/C2 indicators, and off-hours external access.
   - **Isolation Forest (Unsupervised)**: Seeded ensemble of binary isolation trees measuring average path length $h(x)$ and anomaly score $s(x, n) = 2^{-E(h(x))/c(n)}$.
   - **Logistic Regression (Supervised)**: L2-regularized gradient-descent classifier trained on a 10-feature standardized vector.
4. **MITRE ATT&CK Mapping & Defensive Playbooks**: Maps detections to tactics and techniques (`TA0006/T1110.001`, `TA0043/T1046`, `TA0001/T1078`, `TA0004/T1548`, `TA0002/T1059`, `TA0011/T1071`) with actionable response steps.
5. **Explainable AI (XAI) Module**: Displays per-detection rule triggers, Isolation Forest average path length, Logistic Regression probability, statistical Z-score, and exact per-feature signed contributions ($w_i \cdot x_i$).
6. **Attack Correlation Engine**: Automatically groups multi-stage alerts sharing a source IP across time into ordered kill-chain sequences with interactive timeline visualization.
7. **ML Evaluation Lab & Analyst Feedback**:
   - Reproducible 240-record labeled benchmark dataset (`seed = 2026`).
   - Leakage-free preprocessing (Z-score scaler fit strictly on the Training split before transforming the Test split).
   - Genuine computed Accuracy, Precision, Recall, F1-Score, False-Positive Rate, and Confusion Matrices for Isolation Forest, Logistic Regression, and Hybrid Ensemble.
   - True Positive / False Positive analyst feedback loop can be included in Administrator-triggered retraining.
8. **Digital Forensics**: SHA-256 chain-of-custody evidence digests, raw artifact preservation, timeline reconstruction, containment status tracking, and investigator notes.
9. **Threat Intelligence**: Private RFC 1918/loopback/link-local vs. Public IP classification, offline demonstration feed (`Demo Intelligence`), and explicit opt-in manual lookup against public RIPE RDAP (`Verified Public Feed`) with SSRF protection blocking private ranges.
10. **RBAC & Immutable Audit Logging**: Separates **Analyst** (triage, upload, feedback, forensics) and **Administrator** (sensitivity tuning, ML retraining, demo reset) permissions; records every status change, feedback, forensic note, and configuration edit.
11. **Incident Reports, Analytics & REST API Docs**: Interactive analytical filters, CSV/JSON report export, print-ready incident summary, and live REST API endpoint reference.

---

## Architecture Overview

```
React 19 + TypeScript SOC Frontend
   │  (REST JSON + Bearer Token)
   ▼
Express REST API (server.ts / server/routes.ts)
   ├── server/parsers.ts          (CSV, JSON, Syslog TXT validation & normalization)
   ├── server/features.ts         (10-dim behavioral/temporal extraction & train-only scaler)
   ├── server/mlEngine.ts         (Seeded Isolation Forest + L2 Logistic Regression + Evaluator)
   ├── server/detectionEngine.ts  (Rule engine, MITRE ATT&CK, XAI, Playbooks, Correlator)
   ├── server/intel.ts            (IP scope classifier, Demo intel, SSRF-safe RDAP lookup)
   ├── server/auth.ts             (scrypt password hashing, HMAC Bearer tokens, RBAC)
   └── server/store.ts            (Atomic local JSON persistence in data/sentinelforge-store.json)
```

---

## Local Setup & Installation

### Prerequisites
- Node.js `v22+` (native TypeScript execution supported)
- npm `v10+`

### Steps
```bash
# 1. Install dependencies
npm install

# 2. Optional: copy environment template
cp .env.example .env

# 3. Start development server (Express + Vite on port 3000)
npm run dev
```

Open `http://localhost:3000` in your browser.

### Production Build & Start
```bash
npm run build
NODE_ENV=production npm start
```

---

## Docker Deployment

```bash
# Build and start with persistent volume for local JSON storage
docker compose up --build -d
```

SentinelForge will be available at `http://localhost:3000` with data persisted in the `sentinelforge_data` volume.

---

## Demo Accounts (Local Demonstration Only)

SentinelForge opens directly into the SOC workspace for immediate inspection. To test role-based permissions and attributed audit logging, click **Demo Sign-In** in the header:

| Role | Username | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **SOC Analyst** | `analyst` | `analyst-demo-2026` | Upload logs, acknowledge/resolve alerts, submit TP/FP feedback, manage forensics |
| **Administrator** | `admin` | `admin-demo-2026` | All Analyst permissions + sensitivity tuning, ML retraining/split tuning, demo reset |

You can also register additional demo Analyst accounts in the Sign-In modal.

---

## Automated Testing & Verification

Run the automated backend unit and integration test suite (Node built-in test runner):

```bash
npm test
```

Tests verify:
- CSV, JSON, and TXT log parsing and malformed row rejection.
- Train-only Z-score scaler fitting (preventing test data leakage).
- Isolation Forest anomaly scoring separation.
- Reproducible 240-record ML evaluation metrics & confusion matrix consistency.
- Private vs. Public IP classification and SSRF blocking on private/metadata ranges.
- Analyst vs. Administrator RBAC enforcement (`401`/`403` vs `200`) and immutable audit logging.

Run TypeScript type checking:

```bash
npm run lint
```

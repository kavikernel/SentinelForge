## 🚀 Live Demo

**Try SentinelForge here:** https://sentinelforge-5gem.onrender.com/
# SentinelForge
### AI-Powered Threat Detection and Security Analytics Platform

SentinelForge is an academic cybersecurity project designed to analyze security logs, identify suspicious activities, detect potential threats using machine learning, and support security analysts through explainable threat intelligence and investigation workflows.

## Overview

SentinelForge combines rule-based detection and machine learning techniques to provide a local-first security analytics platform. It helps users explore security events, investigate suspicious activity, and understand why an event may have been classified as a threat.

## Key Features

- **Security Log Analysis** – Import and analyze CSV, JSON, and TXT security logs.
- **Hybrid Threat Detection** – Combines rule-based detection, Isolation Forest, and Logistic Regression.
- **Threat Alerts** – View, filter, acknowledge, and investigate detected alerts.
- **Explainable AI (XAI)** – Provides feature-based explanations for model predictions.
- **Attack Correlation** – Correlates related events into potential attack sequences.
- **MITRE ATT&CK Mapping** – Connects detected activity with relevant ATT&CK techniques.
- **Threat Intelligence** – Performs local IP classification with optional public RDAP lookups.
- **Digital Forensics** – Supports investigation records, evidence preservation, and SHA-256 hashing.
- **Security Analytics Dashboard** – Displays event statistics, alert severity, and threat trends.
- **Incident Reports** – Export reports in CSV, JSON, and PDF formats.
- **Role-Based Access Control** – Supports Analyst and Administrator roles.
- **Audit Trail** – Records important platform activities.
- **ML Evaluation Lab** – Retrains and evaluates models using reproducible synthetic datasets.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React 19, TypeScript |
| Styling | CSS |
| Backend | Node.js, Express |
| Build Tool | Vite |
| Machine Learning | Isolation Forest, Logistic Regression |
| Data Storage | Local JSON Store |
| Testing | Node.js Test Runner |
| Development | Git, GitHub, VS Code |

## Architecture

The platform follows a frontend-and-backend architecture:

1. The React frontend provides the security operations interface.
2. The Express backend handles API requests and application logic.
3. The log parser normalizes supported security log formats.
4. The detection engine analyzes events using rules and machine learning.
5. The analytics and investigation modules present alerts, explanations, and correlated activity.
6. The local JSON store maintains application data.

## Installation and Setup

### Prerequisites

- Node.js (a recent supported version)
- npm
- Git

### 1. Clone the repository

```bash
git clone https://github.com/kavikernel/SentinelForge.git
```

### 2. Open the project folder

```bash
cd SentinelForge
```

### 3. Install dependencies

```bash
npm install
```

### 4. Start the application

```bash
npm run dev
```

### 5. Open in your browser

```text
http://localhost:3000
```

## Available Commands

| Command | Description |
|---|---|
| `npm run dev` | Start development server |
| `npm test` | Run automated tests |
| `npm run lint` | Check TypeScript errors |
| `npm run build` | Build the frontend |
| `npm run preview` | Preview the production frontend |

## Testing and Validation

The project was tested with:

- Log parsing and input validation
- Machine learning pipeline and data leakage prevention
- Threat intelligence and SSRF safeguards
- API functionality and role-based access control
- Audit logging and event consistency
- CSV, JSON, and PDF report exports

**Latest recorded automated test result:** 13 tests passed, 0 failed.

The synthetic ML evaluation dataset is intended for academic experimentation. Its results should not be interpreted as guaranteed real-world detection performance.

## Security and Limitations

- Designed as a defensive cybersecurity and academic research prototype.
- Uses synthetic demonstration data.
- Public RDAP lookups are optional.
- Private and reserved IP addresses are not sent to external RDAP services.
- Demo authentication must not be treated as production-grade authentication.
- The platform has not been independently audited or validated for production SOC deployment.

## Future Enhancements

- Integration with additional SIEM and log sources.
- More diverse real-world security datasets.
- Advanced threat correlation.
- Improved model explainability.
- Production-grade authentication and database integration.
- Deployment and monitoring support.

## Project Information

**Project Name:** SentinelForge  
**Category:** Cybersecurity / Artificial Intelligence / Machine Learning  
**Project Type:** Academic Engineering Project  
**Repository:** https://github.com/kavikernel/SentinelForge

---

*SentinelForge — Turning security events into actionable insights.*

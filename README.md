<div align="center">

# 🛡️ PhishGuard Enterprise AI

### Dual-Engine Phishing Defense & Live Cyber Threat Intelligence Platform

[![CI Testing](https://github.com/deepanshuRajput91134/ai-phishing-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/deepanshuRajput91134/ai-phishing-detector/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.143+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40+-FF4B4B.svg?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)

An enterprise-grade, multi-layered cyber defense platform designed to analyze, score, and neutralize modern social engineering, brand typosquatting, freshly registered domains (ICANN RDAP), SSL/TLS misconfigurations, email spoofing, and QR-code phishing (Quishing) in real time.

</div>

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph Inputs["Threat Ingestion Layer"]
        A1["Suspicious URL"] --> PRE
        A2["Email Text / Subject"] --> PRE
        A3["Raw .EML RFC 822 File"] --> PRE
        A4["QR Code Attachment / Quishing"] --> PRE
    end

    subgraph PRE["Preprocessing & Feature Engineering"]
        F1["Domain Shannon Entropy"]
        F2["Lexical & Heuristic Extraction"]
        F3["TF-IDF N-Gram Vectorizer"]
        F4["Homoglyph & Punycode Resolver"]
        F5["Header SPF/DKIM/DMARC Auditor"]
    end

    subgraph LiveIntel["🌐 Live Network & Threat Feeds"]
        L1["📅 ICANN RDAP Domain Age (<30d Alert)"]
        L2["🔒 SSL/TLS Certificate Posture & Issuance Age"]
        L3["🛡️ VirusTotal Multi-Vendor AV Consensus"]
    end

    subgraph AI["Machine Learning & Threat Intelligence"]
        M1["🌲 Random Forest Classifier<br/>(120 Estimators, 24 Lexical Features)"]
        M2["🧠 Hybrid NLP + Behavioral Stacking<br/>(Logistic Regression + Metadata)"]
        M3["🎯 Brand Typosquatting Radar<br/>(50+ High-Value Monitored Targets)"]
    end

    subgraph Output["Defense & Delivery Surfaces"]
        O1["🖥️ Streamlit Enterprise Dashboard"]
        O2["⚡ FastAPI High-Throughput REST API"]
        O3["🧩 Chrome / Edge Browser Extension"]
        O4["📋 SOC Incident Response Playbook & HTML Report"]
    end

    PRE --> AI
    LiveIntel --> AI
    AI --> Output
```

---

## 🌟 Key Defensive Innovations

### 1. 🌐 Live Threat Intelligence & WHOIS Feeds (New in v2.2)
* **ICANN RDAP Domain Age Analysis:** Automatically computes domain registration age. Newly registered domains (<30 days old) receive an immediate critical threat penalty.
* **SSL/TLS Certificate Posture Audit:** Inspects Certificate Authorities (CAs), newly minted SSL certificates (<7 days old), expiration timelines, and SAN depth.
* **VirusTotal Multi-Engine Reputation:** Query 70+ global antivirus vendors for community consensus (optional API key configuration).

### 2. 🎯 Brand Typosquatting & Homoglyph Radar
* **50+ Monitored Enterprise Targets:** Covers global banking (PayPal, Chase, Wells Fargo, Binance), Big Tech (Apple, Microsoft, Google, Netflix), logistics (DHL, FedEx, USPS), and government portals.
* **Homoglyph & Edit Distance Resolution:** Exposes deceptive visual substitutions such as `paypa1.com`, `rnicrosoft.com`, `g00gle.com`.
* **Combosquatting & Subdomain Traps:** Unmasks brand-keyword coupling (`paypal-security-alert.xyz`) and mobile address bar deception (`apple.com.secure-auth.top`).

### 3. 🧠 Explainable AI (XAI) Social Engineering Highlighter
Provides transparent, color-coded visual evidence of the exact psychological lures triggering the AI:
* 🔴 **Red:** Credential Harvesting Lures (*"verify your password"*, *"enter card PIN"*)
* 🟠 **Orange:** Psychological Urgency & Panic Triggers (*"account suspended within 24 hours"*)
* 🟡 **Yellow:** Financial & Prize Lures (*"wire transfer"*, *"tax refund"*, *"overdue invoice"*)
* 🟣 **Purple:** Impersonal Salutations (*"Dear Customer / Valued Member"*)
* 🔵 **Blue:** Embedded Target Hyperlinks

### 4. 📧 Raw RFC 822 (.EML) Header & Spoof Auditor
* **Domain Alignment Checks:** Verifies `From` vs `Reply-To` vs `Return-Path` to prevent identity spoofing.
* **Authentication Validation:** Parses SPF results, DKIM cryptographic signatures, and DMARC enforcement.
* **Attachment Armor:** Flags malicious executables and script payloads (`.exe`, `.scr`, `.iso`, `.hta`, `.vbs`, `.js`, `.xlsm`).

### 5. 📷 Quishing (QR Phishing) Defense Engine
* Scans uploaded images, invoices, and email screenshots for hidden QR barcodes.
* Automatically decodes the underlying URL and routes it through PhishGuard's live threat intelligence and brand-impersonation engine.

### 6. 📋 Automated Executive Incident Reports & SOC Playbooks
* Generates clean, branded **HTML Security Incident Reports** with CVSS-style severity grading.
* Outputs actionable, step-by-step remediation procedures for SOC analysts (Perimeter containment, identity revocation, and mailbox search & destroy).

---

## 🚀 Quickstart Guide

### Option A: 🐳 Docker & Docker Compose (Recommended)

Run the entire ecosystem (Streamlit UI + FastAPI REST server) in one command:
```bash
docker compose up --build
```
* **Web Dashboard:** [http://localhost:8501](http://localhost:8501)
* **API Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option B: 🐍 Local Python Virtual Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/deepanshuRajput91134/ai-phishing-detector.git
   cd ai-phishing-detector
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the services:**
   * **Streamlit Web UI:**
     ```bash
     streamlit run app.py
     ```
   * **FastAPI Server (in a separate terminal):**
     ```bash
     uvicorn api:app --host 0.0.0.0 --port 8000 --reload
     ```

---

## 💻 Command Line Interface (CLI)

Perform lightning-fast scans directly from your terminal:

```bash
# Scan a suspicious URL with Live Network Intel (Domain Age & SSL audit)
python cli.py --url "http://paypa1-security.xyz/login.php" --live-intel

# Audit an exported raw email (.eml) file
python cli.py --email-file "sample.eml" --live-intel

# Scan email text and subject directly
python cli.py \
  --subject "URGENT: Your account has been suspended" \
  --email-text "Dear Customer, Unauthorized charges detected. Verify your card immediately: http://192.168.1.50/bank/login.php"
```

---

## ⚡ REST API Endpoints

FastAPI provides an interactive OpenAPI / Swagger documentation at `http://localhost:8000/docs`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan-url` | Analyzes URLs for structural anomalies, brand impersonation & live WHOIS |
| `POST` | `/api/scan-email` | Evaluates email text with NLP & outputs XAI highlighted HTML |
| `POST` | `/api/deep-scan` | Correlates email content with all extracted embedded links |
| `POST` | `/api/scan-eml` | Multipart upload for RFC 822 `.eml` header & attachment audit |
| `POST` | `/api/scan-qr` | Inspects QR code images for Quishing threat vectors |
| `GET` | `/api/threat-intel/domain-age` | Returns domain registration age & registrar via ICANN RDAP |
| `GET` | `/api/threat-intel/ssl-audit` | Audits SSL/TLS certificate issuer, validity days & self-signed status |
| `POST` | `/api/export-report` | Generates a publication-ready Executive Incident Report (HTML) |
| `GET` | `/api/metrics` | Returns live classifier accuracy, precision, recall & F1 scores |

---

## 🧪 Automated Testing

PhishGuard includes a complete suite of unit and integration tests powered by PyTest:

```bash
pytest tests/ -v
```

All 21 tests validate live threat intelligence, RDAP domain age, SSL audit, homoglyphs, RFC 822 email parsing, ML inference, and Quishing decoders.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Developed with ❤️ by **[Deepanshu Rajput](https://github.com/deepanshuRajput91134)**.

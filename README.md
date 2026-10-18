# 🛡️ PhishGuard Enterprise AI Threat Intelligence Platform

An enterprise-grade, multi-layered cybersecurity defense ecosystem designed to detect, analyze, and neutralize modern phishing attacks, brand typosquatting, email header spoofing, and social engineering in real time.

---

## 🌟 What Makes This Platform Best-in-Class?

### 1. 🎯 Brand Typosquatting & Homoglyph Radar
* **50+ High-Value Monitored Targets:** Finance (PayPal, Chase, Wells Fargo, Binance), Big Tech (Apple, Microsoft, Google), Logistics (DHL, FedEx, USPS), and Government services.
* **Character Substitution / Homoglyphs:** Detects visual tricks like `paypa1.com`, `rnicrosoft.com`, `g00gle.com`.
* **Combosquatting & Subdomain Traps:** Flags deceptive keywords combined with brands (`paypal-security-alert.xyz`) and subdomains intended to deceive users (`apple.com.secure-auth.top`).
* **IDN Punycode Detection:** Identifies internationalized domain name attacks (`xn--...`).

### 2. 🧠 Explainable AI (XAI) Social Engineering Highlighter
* Translates machine learning decisions into **visual, color-coded evidence**:
  * 🔴 **Red:** Credential Harvesting Lures (*"verify password"*, *"enter your PIN"*)
  * 🟠 **Orange:** Psychological Urgency & Panic Triggers (*"account suspended within 24 hours"*)
  * 🟡 **Yellow:** Financial & Prize Scams (*"wire transfer"*, *"tax refund"*, *"overdue invoice"*)
  * 🟣 **Purple:** Impersonal Phishing Salutations (*"Dear Customer/Member"*)
  * 🔵 **Blue:** Embedded Hyperlinks

### 3. 📧 Raw RFC 822 (.EML) Header & Spoof Auditor
* **Email Spoofing Detection:** Checks domain alignment between `From`, `Reply-To`, and `Return-Path` to spot identity spoofing.
* **Authentication Validation:** Parses SPF, DKIM cryptographic signatures, and DMARC enforcement.
* **Attachment Armor:** Flags malicious executable payloads (`.exe`, `.scr`, `.iso`, `.hta`, `.vbs`, `.js`) and suspicious compressed archives.

### 4. ⚡ High-Performance FastAPI REST Server
* Live on `http://localhost:8000` with interactive Swagger UI at `http://localhost:8000/docs`.
* Endpoints for URL scanning, text NLP analysis, `.eml` file auditing, and XAI highlight generation.

### 5. 🧩 Chrome / Edge Browser Extension
* Instant 1-click active tab scanning.
* Real-time brand spoofing alerts right inside your browser toolbar.

### 6. 📋 SOC Analyst Incident Logging & Export
* Logs every inspection in the session with 1-click export to **CSV** or **JSON** for security escalation.

---

## 📁 Directory Structure

```text
ai_phishing_detector/
├── app.py                      # Enterprise Streamlit Web Dashboard
├── api.py                      # FastAPI REST API Server (Port 8000)
├── cli.py                      # Command-Line Scanner with .EML & Brand Intel
├── requirements.txt            # Python Dependencies
├── README.md                   # System Documentation
├── browser_extension/          # Chrome / Edge Extension (Manifest V3)
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── README.md
├── data/                       # Training Datasets (3000 URLs, 2400 Emails)
├── models/                     # Trained Model Artifacts (.joblib)
├── src/                        # Core AI & Threat Intel Modules
│   ├── domain_intel.py         # Brand Typosquatting & Homoglyph Radar
│   ├── eml_parser.py           # RFC 822 EML Header Spoof Auditor
│   ├── xai_highlighter.py      # Explainable AI (XAI) Visual Text Marker
│   ├── features.py             # Feature Extraction (Entropy, RegEx, NLP)
│   ├── dataset_generator.py    # Dataset Synthesis & CSV Loader
│   ├── train.py                # Dual Model Training & Metrics
│   └── predictor.py            # Unified Inference Engine
└── venv/                       # Dedicated Python Virtual Environment
```

---

## ⚡ Quickstart

### 1. Launch Services
* **Web Dashboard:**
  ```bash
  cd /Users/deepanshu/.gemini/antigravity/scratch/ai_phishing_detector
  ./venv/bin/streamlit run app.py
  ```
  Open: `http://localhost:8501`

* **FastAPI Server:**
  ```bash
  cd /Users/deepanshu/.gemini/antigravity/scratch/ai_phishing_detector
  ./venv/bin/uvicorn api:app --host 0.0.0.0 --port 8000
  ```
  Open Docs: `http://localhost:8000/docs`

---

### 2. Run CLI Scans

* **URL Brand Spoofing Check:**
  ```bash
  ./venv/bin/python cli.py --url "http://paypa1-security.xyz/login.php"
  ```

* **Raw .EML File Audit:**
  ```bash
  ./venv/bin/python cli.py --email-file "sample.eml"
  ```

# 🧩 PhishGuard AI - Browser Extension

This extension integrates directly with your local **PhishGuard AI FastAPI server** to protect your browsing in real time.

---

## 🛠️ How to Load in Google Chrome / Brave / Edge

1. Open **Google Chrome** and navigate to:
   ```text
   chrome://extensions
   ```
2. In the top right corner, toggle on **"Developer mode"** (डेवलपर मोड चालू करें).
3. Click on the **"Load unpacked"** (लोड अनपैक्ड) button in the top left.
4. Select this directory:
   ```text
   /Users/deepanshu/.gemini/antigravity/scratch/ai_phishing_detector/browser_extension
   ```
5. Click **Select / Open**.
6. The **PhishGuard AI** shield icon will appear in your Chrome toolbar!

---

## 🚀 How It Works
* Make sure the FastAPI server is running:
  ```bash
  ./venv/bin/uvicorn api:app --host 0.0.0.0 --port 8000
  ```
* When you visit any website, click the **PhishGuard AI** icon in your browser:
  * It will automatically detect the active tab's URL.
  * Click **"🔍 Scan URL"** to see instant threat evaluation, risk score, and heuristic flags!
  * You can also switch to the **"Email Inspector"** tab to paste and analyze suspicious emails and phishing lures.

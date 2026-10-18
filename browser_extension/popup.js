const API_BASE = "http://localhost:8000";

document.addEventListener("DOMContentLoaded", () => {
  const tabUrlBtn = document.getElementById("tab-url-btn");
  const tabEmailBtn = document.getElementById("tab-email-btn");
  const urlPanel = document.getElementById("url-panel");
  const emailPanel = document.getElementById("email-panel");

  const urlInput = document.getElementById("url-input");
  const scanUrlBtn = document.getElementById("scan-url-btn");

  const emailSubject = document.getElementById("email-subject");
  const emailBody = document.getElementById("email-body");
  const scanEmailBtn = document.getElementById("scan-email-btn");

  const resultBox = document.getElementById("result-box");
  const resultBadge = document.getElementById("result-badge");
  const resultScore = document.getElementById("result-score");
  const resultDetail = document.getElementById("result-detail");
  const resultFlags = document.getElementById("result-flags");

  // Tab switching
  tabUrlBtn.addEventListener("click", () => {
    tabUrlBtn.classList.add("active");
    tabEmailBtn.classList.remove("active");
    urlPanel.style.display = "block";
    emailPanel.style.display = "none";
    resultBox.style.display = "none";
  });

  tabEmailBtn.addEventListener("click", () => {
    tabEmailBtn.classList.add("active");
    tabUrlBtn.classList.remove("active");
    emailPanel.style.display = "block";
    urlPanel.style.display = "none";
    resultBox.style.display = "none";
  });

  // Pre-fill active tab URL if available
  if (chrome && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        const currentUrl = tabs[0].url;
        if (currentUrl.startsWith("http://") || currentUrl.startsWith("https://")) {
          urlInput.value = currentUrl;
        }
      }
    });
  }

  // Scan URL
  scanUrlBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    if (!url) {
      alert("Please enter a URL to scan.");
      return;
    }

    scanUrlBtn.disabled = true;
    scanUrlBtn.innerText = "Analyzing...";
    resultBox.style.display = "none";

    try {
      const response = await fetch(`${API_BASE}/api/scan-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      let extraDetail = `Confidence: ${(data.probability * 100).toFixed(1)}%`;
      if (data.brand_intelligence && data.brand_intelligence.impersonated) {
        extraDetail = `🎯 Brand Spoofing: ${data.brand_intelligence.target_brand} (${data.brand_intelligence.attack_type})`;
      }

      displayResult(data.risk_score, data.verdict, data.severity, data.red_flags, extraDetail);
    } catch (err) {
      displayError("Could not connect to PhishGuard API at http://localhost:8000. Ensure the FastAPI backend is running.");
    } finally {
      scanUrlBtn.disabled = false;
      scanUrlBtn.innerText = "🔍 Scan URL";
    }
  });

  // Scan Email
  scanEmailBtn.addEventListener("click", async () => {
    const subject = emailSubject.value.trim();
    const body = emailBody.value.trim();
    if (!subject && !body) {
      alert("Please provide email subject or body.");
      return;
    }

    scanEmailBtn.disabled = true;
    scanEmailBtn.innerText = "Analyzing...";
    resultBox.style.display = "none";

    try {
      const response = await fetch(`${API_BASE}/api/deep-scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subject: subject, body: body })
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      const flags = (data.email_analysis.red_flags || []);
      const linksCount = (data.extracted_urls || []).length;
      displayResult(
        data.composite_risk_score,
        data.composite_verdict,
        data.composite_severity,
        flags,
        `Embedded Links Audited: ${linksCount}`
      );
    } catch (err) {
      displayError("Could not connect to PhishGuard API at http://localhost:8000. Ensure the FastAPI backend is running.");
    } finally {
      scanEmailBtn.disabled = false;
      scanEmailBtn.innerText = "🔬 Scan Email";
    }
  });

  function displayResult(score, verdict, severity, flags, detail) {
    resultBox.style.display = "block";
    resultScore.innerText = `Risk: ${score}/100`;
    resultBadge.innerText = verdict;
    resultBadge.className = "badge";

    if (severity === "danger" || score >= 70) {
      resultBadge.classList.add("badge-danger");
      resultScore.style.color = "#ef4444";
    } else if (severity === "warning" || score >= 40) {
      resultBadge.classList.add("badge-warning");
      resultScore.style.color = "#f59e0b";
    } else {
      resultBadge.classList.add("badge-success");
      resultScore.style.color = "#10b981";
    }

    resultDetail.innerText = detail || "";
    resultFlags.innerHTML = "";

    if (flags && flags.length > 0) {
      flags.forEach((flag) => {
        const li = document.createElement("li");
        li.innerText = `🚩 ${flag}`;
        resultFlags.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.style.color = "#a7f3d0";
      li.innerText = "🟢 No malicious indicators detected.";
      resultFlags.appendChild(li);
    }
  }

  function displayError(msg) {
    resultBox.style.display = "block";
    resultScore.innerText = "Connection Error";
    resultScore.style.color = "#ef4444";
    resultBadge.innerText = "API Offline";
    resultBadge.className = "badge badge-danger";
    resultDetail.innerText = msg;
    resultFlags.innerHTML = "";
  }
});

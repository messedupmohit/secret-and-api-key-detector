# Secret & API Key Detector

A lightweight **Blue Team / Detection Engineering** tool designed to identify hardcoded secrets and sensitive information in source code and text files.

This project simulates an **internal security utility** commonly used during:

- Secure code reviews
- Incident response
- DevSecOps pipelines
- Post-breach investigations

The tool is intentionally simple, fast, and analyst-focused.

---

## 📌 What This Tool Detects

The scanner uses pattern-based detection to identify:

- Cloud credentials (e.g. AWS access keys)
- API keys (GitHub, Google, generic)
- Tokens (JWTs)
- Hardcoded passwords
- Usernames
- Email addresses

All detections include:

- File name
- Line number
- Secret type
- Severity
- Masked value (with optional reveal)

---

## 🧠 Why This Matters (Blue Team Context)

Leaked credentials are one of the most common root causes of:

- Cloud account compromise
- Supply chain attacks
- Data breaches
- Privilege escalation incidents

Tools like this are routinely used in:

- SOC investigations
- Secure SDLC enforcement
- Breach containment and scoping

Real-world equivalents include:

- GitHub Secret Scanning
- TruffleHog
- Gitleaks

---

## 🖥️ Features

- Scan a **single file** or **entire directory**
- GUI and CLI-friendly design
- Masked secrets by default (safe handling)
- Explicit toggle to reveal full values
- Filter results by secret type
- Export findings to CSV
- No cloud dependencies
- No external services required

---

## 📂 Project Structure

secret-and-api-key-detector/
├── gui.py
├── scanner.py
├── patterns.py
├── README.md
├── screenshot/
│ └── app_ui.png
└── test_files/
└── pickme.txt

---

## 🚀 How to Run

### 1. Install dependency

```bash
pip install ttkbootstrap
```

### 2. Launch the GUI

python gui.py

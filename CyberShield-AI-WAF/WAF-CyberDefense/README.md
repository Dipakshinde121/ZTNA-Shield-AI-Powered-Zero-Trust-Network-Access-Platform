# 🛡️ CyberShield WAF — Web Application Firewall

> **AI-Powered Web Application Firewall Dashboard & Assistant**  
> A professional cyber security project built in pure Python with Streamlit  
> *College PBL Project | GitHub Portfolio | SOC Dashboard*

---

## 📌 Project Overview

**CyberShield WAF** is a real-time Web Application Firewall (WAF) that monitors, detects, and blocks malicious HTTP requests. The project features an enterprise-grade cybersecurity dashboard inspired by real-world Security Operations Centers (SOCs) and a built-in AI help bot.

### 🔐 What It Does
- Inspects incoming requests for **6 attack categories**
- Blocks and logs all detected threats with **severity scoring**
- Displays a live **SOC-style dashboard** with animated charts
- Provides a **forensic attack log** with filtering capabilities
- Shows **system health status** and module uptime
- Offers an interactive **AI Security Chatbot** (SHIELD-AI) for payload analysis and OWASP queries

---

## 🚀 Features

| Feature | Description |
|---|---|
| 🤖 AI Threat Engine | Pattern-matching detection across 6 attack categories |
| 🚫 Attack Blocking | Instant block alerts with detailed threat breakdown |
| 📊 Live Dashboard | Real-time stats and Matplotlib-based distribution charts |
| 📋 Attack Logs | Full forensic log with filter by type/severity |
| ⚙️ System Status | Module health, resource usage, and OWASP coverage |
| 🤖 SHIELD-AI Bot | Interactive security chat helper with local + Gemini API support |
| 🎨 Cyber UI | Neon dark theme, metrics formatting, and custom style rules |

---

## 🛡️ Attack Detection Coverage

| Attack Type | Severity | Examples |
|---|---|---|
| SQL Injection | HIGH | `' OR 1=1 --`, `UNION SELECT` |
| Cross-Site Scripting (XSS) | HIGH | `<script>alert(1)</script>` |
| Command Injection | CRITICAL | `; cat /etc/passwd` |
| Directory Traversal | HIGH | `../../etc/shadow` |
| Remote Code Execution | CRITICAL | `base64_decode(...)` |
| Suspicious HTTP | MEDIUM | Config file probing, PHP shells |

---

## 📁 Project Structure

```
WAF-CyberDefense/
├── app.py                  # Main Streamlit App: WAF engine, UI layout, chatbot
├── requirements.txt        # Python dependencies (Streamlit, Matplotlib, Pandas)
├── attack_logs.json        # JSON-based attack log database
└── README.md
```

---

## ⚡ Quick Start (VS Code / Terminal)

### 1. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the application
```bash
streamlit run app.py
```

### 3. Open in browser
```
http://localhost:8501
```

---

## 🧪 Test Payloads

Try these in the **Request Analyzer** on the dashboard:

```sql
-- SQL Injection
' OR 1=1 --
UNION SELECT * FROM users

-- XSS
<script>alert('XSS')</script>

-- Command Injection
; cat /etc/passwd

-- Directory Traversal
../../etc/shadow

-- Safe Request
Hello World
```

---

## 🛠️ Tech Stack

- **Framework:** Python 3, Streamlit
- **Data & Charts:** Pandas, Matplotlib
- **AI Integration:** Google Gemini API (optional, via environment key) or Local Rule-Based Expert System
- **Design:** SOC dashboard, custom CSS dark neon injection

---

## 🎓 Academic Context

This project demonstrates understanding of:
- **OWASP Top 10** web application vulnerabilities
- **Regex-based signature detection** (core WAF technique)
- **Threat scoring and severity classification**
- **Forensic logging** for incident response
- **AI Chat Agent Design** with RAG context mapping
- **Data visualization** with Matplotlib

---

## 👤 Author

**[Your Name]** — Computer Science / Cybersecurity  
*College PBL Project — [Year]*

---

*CyberShield WAF is a student project for educational purposes.*

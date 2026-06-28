# 🛡️ CyberShield AI-WAF — Web Application Firewall & SOC Dashboard

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B.svg?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Security](https://img.shields.io/badge/OWASP-Top--10-green.svg)](https://owasp.org/www-project-top-ten/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**CyberShield AI-WAF** is a real-time Web Application Firewall (WAF) and Security Operations Center (SOC) dashboard built entirely in Python. The system utilizes signature-based regex heuristics to intercept, score, and block malicious HTTP traffic across common OWASP vulnerabilities, and integrates an AI Security Assistant (**SHIELD-AI**) to provide forensic threat analysis and Q&A.

---

## 📌 Features & Core Capabilities

- **🎛️ Live SOC Dashboard**: Real-time traffic monitoring showcasing Total Requests, Blocked Attacks, Safe Requests, Uptime, Packet Rates, and overall system Threat Levels.
- **🤖 Heuristics Engine**: Pattern-matching signatures for 6 major categories of cyber threats (SQL Injection, Cross-Site Scripting, Command Injection, Directory Traversal, Remote Code Execution, and Suspicious HTTP probes).
- **📊 Interactive Analytics**: Matplotlib data visualizations illustrating the distribution of blocked threat types.
- **📋 Forensic Attack Logs**: A comprehensive log repository featuring advanced multi-parameter filters (by severity and attack type) for security incident responders.
- **⚙️ Threat Intelligence**: System health resource gauges and a mitigation mapping matrix mapped against the **OWASP Top 10**.
- **💬 SHIELD-AI Chat Helper**: A smart conversational security agent with hybrid capabilities:
  - **Local Mode (Offline)**: Interrogates live log databases, parses payload patterns, and explains vulnerabilities.
  - **Cognitive Mode (Online)**: Integrates with Google's Gemini LLM API to provide deep, contextual threat insights based on active WAF metrics.

---

## 📸 SOC Dashboard Previews

### Main Operations Dashboard
![Dashboard](WAF-CyberDefense/Screenshots/dashboard.png)

### Real-Time Request Analysis & Alerts
![SQL Detection](WAF-CyberDefense/Screenshots/sql_detection.png)

### Forensic Attack Logs
![Attack Logs](WAF-CyberDefense/Screenshots/logs.png)

---

## 📂 Repository Structure

```
CyberShield-AI-WAF/
├── WAF-CyberDefense/
│   ├── app.py                  # Main Python application (Streamlit dashboard & bot)
│   ├── requirements.txt        # Python dependencies (Streamlit, Matplotlib, Pandas)
│   ├── attack_logs.json        # Persistent JSON log database
│   └── Screenshots/            # System screenshots and figures
└── README.md                   # Repository landing page
```

---

## ⚡ Quick Start (Local Setup)

### Prerequisites
Ensure Python 3.9+ is installed on your local operating system.

### 1. Clone the Repository
```bash
git clone https://github.com/Dipakshinde121/ZTNA-Shield-AI-Powered-Zero-Trust-Network-Access-Platform.git
cd ZTNA-Shield-AI-Powered-Zero-Trust-Network-Access-Platform/WAF-CyberDefense
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
streamlit run app.py
```
*The application will automatically launch in your default browser at `http://localhost:8501`.*

---

## ☁️ Streamlit Cloud Deployment

This project is fully compatible with **Streamlit Cloud** for instant public sharing.

1. Push your changes to your GitHub repository.
2. Go to [share.streamlit.io](https://share.streamlit.io/) and log in.
3. Click **Deploy an app**, then select your repository and branch.
4. Set the **Main file path** to: `WAF-CyberDefense/app.py`
5. *(Optional)* Add your `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) to the App's **Advanced Settings -> Secrets** to unlock advanced AI chatbot functionality.
6. Click **Deploy!**

---

## 🔬 Threat Detection Specifications

The firewall filters inputs against pre-defined, high-confidence signatures:

| Attack Vector | Log Severity | Default Score | Sample Payload |
|---|---|---|---|
| **SQL Injection (SQLi)** | `HIGH` | `90 / 100` | `' UNION SELECT username, password FROM users --` |
| **Cross-Site Scripting (XSS)** | `HIGH` | `85 / 100` | `<script>alert(document.cookie)</script>` |
| **Command Injection** | `CRITICAL` | `95 / 100` | `; rm -rf /` |
| **Directory Traversal** | `HIGH` | `80 / 100` | `../../etc/passwd` |
| **Remote Code Execution** | `CRITICAL` | `95 / 100` | `base64_decode($_POST['cmd'])` |
| **Suspicious HTTP** | `MEDIUM` | `50 / 100` | `/phpmyadmin/index.php` |

---

## 🎓 Academic & Defensive Principles

This project serves as an educational model demonstrating:
- **Regex-based Input Sanitization**: A fundamental building block of traditional software-level firewalls.
- **Threat Scoring & Incident Classification**: Assigning weights and logs systematically to enable triage.
- **Log Augmentation (RAG)**: Integrating context injection to let an AI assistant read local databases and summarize system states.

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.
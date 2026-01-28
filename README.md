# 🔐 SRTA – Smart Remote Trust Analyzer

SRTA (Smart Remote Trust Analyzer) is a behavior-based cybersecurity monitoring system that evaluates the trustworthiness of a computer system by analyzing runtime activity and detecting potential remote access or suspicious behavior.

Unlike traditional signature-based security tools, SRTA focuses on **system behavior** such as command-line usage and remote access applications to dynamically calculate a **trust score** and classify the system state as SAFE, WARNING, or CRITICAL.

---

## 🚀 Features

- 🛰️ Agent-based real-time system monitoring  
- 🔍 Detection of remote access and command-line tools (AnyDesk, TeamViewer, CMD, PowerShell)  
- 🧠 Dynamic trust score calculation using risk-based logic  
- 📊 Live web dashboard with auto-refresh  
- 🖥️ Desktop UI application for real-time trust status  
- 📜 Activity logging for audit and analysis  
- ⚠️ Behavior-based detection (not signature-based)

---

## 🏗️ Architecture

- **Agent**: Monitors system processes and reports risky activity  
- **Server**: Calculates trust score, stores logs, and exposes APIs  
- **Dashboard / UI App**: Visualizes trust score and system status  

---

## 📁 Project Structure

SRTA version2/
│
├── server.py
├── agent/
│ └── agent.py
├── ui_app.py
├── templates/
│ └── dashboard.html
├── logs/
│ └── activity.log


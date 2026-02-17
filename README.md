# iot-cloud-security-risk-assessment
A rule-based IoT &amp; Cloud Security Risk Assessment Tool

# IoT & Cloud Security Risk Assessment Tool

This repository is a simple Flask web application that demonstrates a rule-based risk assessment for IoT devices and cloud assets. It is an online-only web app and does not connect to physical devices.

Quick start

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2. Run the app:

```bash
python main.py
```

3. Open http://127.0.0.1:5000 in your browser.

What changed

- Added a minimal Flask UI (`main.py`, `templates/`, `static/`).
- Implemented a basic `risk_engine` with `risk_calculator.py` and sample `data/threat_knowledge.json`.

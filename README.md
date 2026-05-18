# iot-cloud-security-risk-assessment
An ML-based IoT & Cloud Security Risk Assessment Tool

**Repository:** https://github.com/Hena757/iot-cloud-security-risk-assessment

# IoT & Cloud Security Risk Assessment Tool

This repository is a Flask web application that demonstrates an ML-based risk assessment for IoT devices and cloud assets. It uses machine learning models trained on threat data to predict risk scores. It is an online-only web app and does not connect to physical devices.

Quick start

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2. Train the ML model (optional, model is pre-trained):

```bash
python train_ml_model.py
```

3. Run the app:

```bash
python main.py
```

4. Open http://127.0.0.1:5000 in your browser.

What changed

- Added machine learning capabilities using scikit-learn RandomForestRegressor.
- Implemented ML-based risk prediction in `risk_engine/ml_model.py`.
- Updated `risk_calculator.py` to use ML predictions for risk scores.
- Added training script `train_ml_model.py`.

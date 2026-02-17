from flask import Flask, render_template, request, redirect, url_for
from risk_engine.risk_calculator import load_threats, analyze_risks
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(__file__)
THREATS_PATH = os.path.join(BASE_DIR, "data", "threat_knowledge.json")


@app.route("/", methods=["GET"]) 
def index():
    threats = load_threats(THREATS_PATH)
    return render_template("index.html", threats=threats)


@app.route("/analyze", methods=["POST"])
def analyze():
    asset_name = request.form.get("asset_name", "Unnamed")
    asset_type = request.form.get("asset_type", "iot")
    mitigation_pct = float(request.form.get("mitigation_pct", 0)) / 100.0

    threats = load_threats(THREATS_PATH)
    results = analyze_risks(threats, asset_type=asset_type, mitigation=mitigation_pct)

    return render_template("report.html", asset_name=asset_name, asset_type=asset_type, results=results, mitigation=int(mitigation_pct*100))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

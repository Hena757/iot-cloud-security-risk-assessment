from flask import Flask, render_template, request, redirect, url_for
from risk_engine.risk_calculator import load_threats, analyze_risks
import os
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

BASE_DIR = os.path.dirname(__file__)
THREATS_PATH = os.path.join(BASE_DIR, "data", "threat_knowledge.json")

# Configure rotating file logging to persist server logs to reports/server_run.log
LOG_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "server_run.log")

handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3)
formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]")
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)

app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Also attach the handler to the werkzeug logger so HTTP requests are logged
logging.getLogger('werkzeug').addHandler(handler)


@app.before_request
def log_request():
    app.logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")
    # Also write a simple, guaranteed append to the log file to avoid issues
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as _lf:
            _lf.write(f"{request.remote_addr} - {request.method} {request.path}\n")
    except Exception:
        pass


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

    # Record analysis summary to log file as well
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as _lf:
            _lf.write(f"ANALYZE: asset={asset_name} type={asset_type} mitigation={mitigation_pct}\n")
    except Exception:
        pass

    return render_template("report.html", asset_name=asset_name, asset_type=asset_type, results=results, mitigation=int(mitigation_pct*100))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

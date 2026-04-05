from flask import Flask, render_template, request, redirect, url_for
from risk_engine.risk_calculator import load_threats, analyze_risks, get_unique_threats
import os
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

BASE_DIR = os.path.dirname(__file__)
THREATS_PATH = os.path.join(BASE_DIR, "data", "raw_dataset.csv")

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


# Custom Jinja filter to get risk level
def get_risk_level(score):
	"""Determine risk level based on risk score"""
	score = float(score)
	if score >= 15:
		return 'critical'
	elif score >= 10:
		return 'high'
	elif score >= 5:
		return 'medium'
	else:
		return 'low'

app.jinja_env.filters['getRiskLevel'] = get_risk_level


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
    threats = get_unique_threats(THREATS_PATH)
    return render_template("index.html", threats=threats)


@app.route("/analyze", methods=["POST"])
def analyze():
    cloud_platform = request.form.get("cloud_platform", "Unknown")
    asset_type = request.form.get("asset_type", "iot")
    mitigation_pct = float(request.form.get("mitigation_pct", 0)) / 100.0

    threats = load_threats(THREATS_PATH)
    results = analyze_risks(threats, asset_type=asset_type, cloud_platform=cloud_platform, mitigation=mitigation_pct)

    # Calculate average risk score
    if results:
        avg_risk_score = sum(r["risk_score"] for r in results) / len(results)
    else:
        avg_risk_score = 0

    # Record analysis summary to log file as well
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as _lf:
            _lf.write(f"ANALYZE: platform={cloud_platform} type={asset_type} mitigation={mitigation_pct} avg_risk={avg_risk_score}\n")
    except Exception:
        pass

    return render_template("report.html", cloud_platform=cloud_platform, asset_type=asset_type, results=results, mitigation=int(mitigation_pct*100), avg_risk_score=round(avg_risk_score, 2))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

import csv
from typing import List, Dict
from .ml_model import predictor


def load_threats(path: str) -> List[Dict]:
	"""Load threat knowledge from CSV file.

	Each threat should have: id, name, scope ("iot"/"cloud"/"both"), likelihood (1-5), impact (1-5), description
	"""
	threats = []
	with open(path, "r", encoding="utf-8") as f:
		reader = csv.DictReader(f)
		for idx, row in enumerate(reader, start=1):
			try:
				likelihood = int(row["Likelihood"])
				impact = int(row["Impact"])
			except (ValueError, KeyError):
				continue  # Skip rows with invalid or missing data
			threat = {
				"id": f"{row['Cloud_Provider']}_{row['Service_Model']}_{idx}",
				"name": row["Threat_Type"],
				"scope": "cloud",
				"cloud_provider": row["Cloud_Provider"],
				"likelihood": likelihood,
				"impact": impact,
				"description": row["Vulnerability"],
				"service_model": row["Service_Model"],
				"region": row["Region"],
				"compliance_risk": row["Compliance_Risk"],
				"data_sensitivity": row["Data_Sensitivity"],
				"mitigation_available": row["Mitigation_Available"]
			}
			threats.append(threat)
	return threats


def analyze_risks(threats: List[Dict], asset_type: str = "iot", cloud_platform: str = None, mitigation: float = 0.0) -> List[Dict]:
	"""Compute risk score for threats relevant to the given asset type and cloud platform.

	risk_score = ML_predicted_risk * (1 - mitigation)
	Returns list of threats with computed `risk_score` sorted descending.
	"""
	relevant = [t for t in threats if t.get("scope", "both") in (asset_type, "both")]
	
	# Filter by cloud platform if specified
	if cloud_platform:
		relevant = [t for t in relevant if t.get("cloud_provider") == cloud_platform]
	
	results = []
	for t in relevant:
		# Use ML model to predict base risk
		features = {
			'Cloud_Provider': t.get('cloud_provider', ''),
			'Service_Model': t.get('service_model', ''),
			'Region': t.get('region', ''),
			'Threat_Type': t.get('name', ''),
			'Vulnerability': t.get('description', ''),
			'Compliance_Risk': t.get('compliance_risk', ''),
			'Data_Sensitivity': t.get('data_sensitivity', ''),
			'Mitigation_Available': t.get('mitigation_available', '')
		}
		base_risk = predictor.predict_risk(features)
		score = base_risk * max(0.0, 1.0 - float(mitigation))
		r = {
			"id": t.get("id"),
			"name": t.get("name"),
			"description": t.get("description", ""),
			"likelihood": t.get("likelihood", 1),
			"impact": t.get("impact", 1),
			"risk_score": round(score, 3),
		}
		results.append(r)
	results.sort(key=lambda x: x["risk_score"], reverse=True)
	return results


def get_unique_threats(path: str) -> List[Dict]:
	"""Load unique threats from CSV file (no duplicates by threat name).
	
	Returns list of unique threats with minimal duplication.
	"""
	threats = load_threats(path)
	seen = set()
	unique = []
	for t in threats:
		if t["name"] not in seen:
			seen.add(t["name"])
			unique.append(t)
	return unique


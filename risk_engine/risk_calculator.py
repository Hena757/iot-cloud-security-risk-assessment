import json
from typing import List, Dict


def load_threats(path: str) -> List[Dict]:
	"""Load threat knowledge from JSON file.

	Each threat should have: id, name, scope ("iot"/"cloud"/"both"), likelihood (1-5), impact (1-5), description
	"""
	with open(path, "r", encoding="utf-8") as f:
		data = json.load(f)
	return data.get("threats", [])


def analyze_risks(threats: List[Dict], asset_type: str = "iot", mitigation: float = 0.0) -> List[Dict]:
	"""Compute risk score for threats relevant to the given asset type.

	risk_score = likelihood * impact * (1 - mitigation)
	Returns list of threats with computed `risk_score` sorted descending.
	"""
	relevant = [t for t in threats if t.get("scope", "both") in (asset_type, "both")]
	results = []
	for t in relevant:
		likelihood = float(t.get("likelihood", 1))
		impact = float(t.get("impact", 1))
		score = likelihood * impact * max(0.0, 1.0 - float(mitigation))
		r = {
			"id": t.get("id"),
			"name": t.get("name"),
			"description": t.get("description", ""),
			"likelihood": likelihood,
			"impact": impact,
			"risk_score": round(score, 3),
		}
		results.append(r)
	results.sort(key=lambda x: x["risk_score"], reverse=True)
	return results


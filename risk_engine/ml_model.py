import joblib
import os
from typing import Dict

class RiskPredictor:
    def __init__(self):
        model_dir = os.path.dirname(__file__)
        self.model = joblib.load(os.path.join(model_dir, 'risk_model.pkl'))
        self.encoders = joblib.load(os.path.join(model_dir, 'label_encoders.pkl'))

    def predict_risk(self, features: Dict[str, str]) -> float:
        """Predict risk score based on features."""
        encoded_features = {}
        for col in ['Cloud_Provider', 'Service_Model', 'Region', 'Threat_Type', 'Vulnerability', 'Compliance_Risk', 'Data_Sensitivity', 'Mitigation_Available']:
            value = features.get(col, '')
            if col in self.encoders:
                try:
                    encoded = self.encoders[col].transform([value])[0]
                except ValueError:
                    # If unseen category, use the first class
                    encoded = 0
                encoded_features[col] = encoded
            else:
                encoded_features[col] = 0
        import pandas as pd
        df = pd.DataFrame([encoded_features])
        return self.model.predict(df)[0]

# Global predictor instance
predictor = RiskPredictor()
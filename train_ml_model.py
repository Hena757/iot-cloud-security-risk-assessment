import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Load the dataset
data_path = os.path.join(os.path.dirname(__file__), 'data', 'raw_dataset.csv')
df = pd.read_csv(data_path)

# Features and target
features = ['Cloud_Provider', 'Service_Model', 'Region', 'Threat_Type', 'Vulnerability', 'Compliance_Risk', 'Data_Sensitivity', 'Mitigation_Available']
target = 'Risk_Score'

# Encode categorical features
le_dict = {}
for col in features:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    le_dict[col] = le

X = df[features]
y = df[target]

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestRegressor(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model and encoders
model_dir = os.path.join(os.path.dirname(__file__), 'risk_engine')
os.makedirs(model_dir, exist_ok=True)
joblib.dump(model, os.path.join(model_dir, 'risk_model.pkl'))
joblib.dump(le_dict, os.path.join(model_dir, 'label_encoders.pkl'))

print("Model trained and saved.")
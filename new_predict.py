import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix

import warnings
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', category=UserWarning)

# Artifacts saved from your training notebook
feature_cols = joblib.load("src/feature_columns.joblib")   # exact training column order
model        = joblib.load("src/hgb_model.joblib")
le           = joblib.load("src/label_encoder.joblib")

data_benign = pd.read_csv("data/benign_traffic_test_order.pcap_Flow.csv")
data_benign['Label'] = 'BENIGN'

data_attack = pd.read_csv("data/attacker_traffic_test_order.pcap_Flow.csv")
data_attack['Label'] = 'ATTACK'

data = pd.concat([data_benign, data_attack], ignore_index=True)

# Normalize names (CIC-IDS2017 CSVs have leading spaces in headers)
data.columns = data.columns.str.strip()
print(data.columns)

# got from training. update accordingly if necessary
final_cols = ['Protocol', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
       'Total Length of Fwd Packet', 'Total Length of Bwd Packet',
       'Fwd Packet Length Max', 'Fwd Packet Length Min',
       'Fwd Packet Length Mean', 'Fwd Packet Length Std',
       'Bwd Packet Length Max', 'Bwd Packet Length Min',
       'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
       'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
       'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
       'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
       'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
       'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
       'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
       'Packet Length Min', 'Packet Length Max', 'Packet Length Mean',
       'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
       'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
       'URG Flag Count', 'CWR Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg',
       'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg',
       'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg',
       'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
       'Subflow Bwd Bytes', 'FWD Init Win Bytes', 'Bwd Init Win Bytes',
       'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std',
       'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max',
       'Idle Min'
       # 'Attack Type', 'Attack Number' <- used later
       ]
data = pd.concat([data_benign, data_attack], ignore_index=True)
data.columns = data.columns.str.strip()

# Keep only TCP flows
print((data['Label'] == 'BENIGN').sum())
data = data[data['Protocol'] == 6].copy()
print((data['Label'] == 'BENIGN').sum())

# Convert label to binary
pred_cols = ['Attack Type']
data.rename(columns={"Label": "Attack Type"}, inplace=True)
data['Attack Type'] = np.where(data['Attack Type'] == 'BENIGN', 0, 1)

# Drop shortcut columns
data = data.drop(columns=['Protocol', 'FWD Init Win Bytes', 'Bwd Init Win Bytes',
                          'Fwd Seg Size Min', 'Packet Length Min',
                          'Fwd Packet Length Min', 'Bwd Packet Length Min'],
                 errors='ignore')

data = data.filter(items=final_cols + ['Attack Type'])
print(data['Attack Type'].value_counts(dropna=False))

# Clean the same way as in training
data = data.replace([np.inf, -np.inf], np.nan).dropna()

data.replace([np.inf, -np.inf], np.nan, inplace = True)

# Filling missing values with median
med_flow_bytes = data['Flow Bytes/s'].median()
med_flow_packets = data['Flow Packets/s'].median()
data['Flow Bytes/s'].fillna(med_flow_bytes, inplace = True)
data['Flow Packets/s'].fillna(med_flow_packets, inplace = True)

print("done cleaning")

# Enforce the training schema and order; fail loudly if columns are missing
missing = set(feature_cols) - set(data.columns)
assert not missing, f"Missing features: {missing}"
y_test = data[pred_cols].copy()
X = data[feature_cols].astype(float)

preds = model.predict(X)
print(preds)
print(np.unique(preds, return_counts=True))
print(le.classes_)

y_pred = model.predict(X)
print(f"Test accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"Test F1:       {f1_score(y_test, y_pred):.4f}")
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred, target_names=["Benign", "Attack"], digits=4))

"""
data['pred'] = y_pred
missed = data[(data['Attack Type'] == 1) & (data['pred'] == 0)]
print(missed[['Protocol','Flow Duration','Total Fwd Packet','Total Bwd packets',
              'Total Length of Fwd Packet','SYN Flag Count','FIN Flag Count']].describe())

raw = model.predict(X)
print(pd.Series(le.inverse_transform(raw)).value_counts())
proba = model.predict_proba(X)
print(pd.Series(proba[:, list(le.classes_).index('BENIGN')]).describe())

cols = ['RST Flag Count','Fwd Seg Size Min','FWD Init Win Bytes','Packet Length Min',
        'Protocol','SYN Flag Count','Fwd Header Length']
print("YOUR CAPTURE median by class")
print(data.groupby('Attack Type')[cols].median().T)
"""

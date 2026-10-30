import numpy as np
import pandas as pd
import joblib

# Artifacts saved from your training notebook
feature_cols = joblib.load("src/feature_columns.joblib")   # exact training column order
model        = joblib.load("src/hgb_model.joblib")
le           = joblib.load("src/label_encoder.joblib")

data = pd.read_csv("flows_output.csv")

# Normalize names (CIC-IDS2017 CSVs have leading spaces in headers)
data.columns = data.columns.str.strip()
print(data.columns)

"""
# Map new-tool names to the training names
rename_map = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    # ... etc.
}
df = df.rename(columns=rename_map)
"""

# got from training. update accordingly if necessary
final_cols = ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
       'Total Backward Packets', 'Total Length of Fwd Packets',
       'Total Length of Bwd Packets', 'Fwd Packet Length Max',
       'Fwd Packet Length Min', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Bwd Packet Length Max',
       'Bwd Packet Length Min', 'Bwd Packet Length Mean',
       'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
       'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
       'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
       'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
       'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags',
       'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
       'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
       'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
       'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
       'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
       'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
       'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Subflow Fwd Packets',
       'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
       'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
       'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
       # 'Attack Type', 'Attack Number'
       # removed for predicting
       ]
data = data[final_cols]
print(data)

# Clean the same way as in training
data = data.replace([np.inf, -np.inf], np.nan).dropna()

data.drop_duplicates(inplace = True)
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
X = data[feature_cols].astype(float)

# Apply the SAME fitted scaler, then predict
preds = model.predict(X)
print(preds)

"""
Week 7 — Random Forest Attack Classifier
Classifies traffic into specific attack types with confidence scores.
Trained on your existing labelled CSV files.
"""

import pandas as pd
import numpy as np
import json, joblib, os
from sklearn.ensemble      import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics       import classification_report, confusion_matrix

# ── Paths ─────────────────────────────────────────────────────
LOGS_DIR   = "/app/logs"
MODEL_DIR  = "/app/models"
os.makedirs(MODEL_DIR, exist_ok=True)

FEATURES = [
    "pps", "bps", "avg_pkt_size", "total_packets",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "syn_ratio", "synack_ratio", "rst_ratio",
    "syn_count", "ack_count", "rst_count", "fin_count",
    "unique_src_ips", "top_ip_ratio",
    "unique_dst_ports", "unique_src_ports",
    "iat_mean", "iat_std"
]

# ── Load all labelled CSV files ────────────────────────────────
print("[1] Loading labelled data...")

files = {
    "normal"    : f"{LOGS_DIR}/training_normal.csv",
    "syn_flood" : f"{LOGS_DIR}/training_syn_flood.csv",
    "udp_flood" : f"{LOGS_DIR}/training_udp_flood.csv",
    "icmp_flood": f"{LOGS_DIR}/training_icmp_flood.csv",
    "http_flood": f"{LOGS_DIR}/training_http_flood.csv",
    "slowloris" : f"{LOGS_DIR}/training_slowloris.csv",
}

dfs = []
for label, path in files.items():
    if os.path.exists(path):
        df = pd.read_csv(path)
        df["attack_type"] = label     # force correct label
        df = df[df["pps"] >= 0.5]    # remove empty windows
        dfs.append(df)
        print(f"    {label:<12} : {len(df)} windows")
    else:
        print(f"    {label:<12} : FILE NOT FOUND — skipping")

df_all = pd.concat(dfs, ignore_index=True)
print(f"\n    Total windows : {len(df_all)}")

# ── Prepare features and labels ────────────────────────────────
print("\n[2] Preparing features...")
X = df_all[FEATURES].fillna(0).values
y_raw = df_all["attack_type"].values

# Encode string labels to integers
encoder = LabelEncoder()
y = encoder.fit_transform(y_raw)

print(f"    Classes : {list(encoder.classes_)}")
print(f"    X shape : {X.shape}")

# ── Scale features ─────────────────────────────────────────────
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ── Train / test split ─────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y,
    test_size    = 0.2,
    random_state = 42,
    stratify     = y
)

print(f"    Train : {len(X_train)} | Test : {len(X_test)}")

# ── Train Random Forest ────────────────────────────────────────
print("\n[3] Training Random Forest Classifier...")

clf = RandomForestClassifier(
    n_estimators = 300,
    max_depth    = None,
    random_state = 42,
    n_jobs       = -1,
    class_weight = "balanced"
)
clf.fit(X_train, y_train)

# ── Evaluate ───────────────────────────────────────────────────
print("\n[4] Evaluating...")
y_pred = clf.predict(X_test)

print("\n    Classification Report:")
print(classification_report(
    y_test, y_pred,
    target_names=encoder.classes_
))

# Feature importance
importances = clf.feature_importances_
top_features = sorted(
    zip(FEATURES, importances),
    key=lambda x: x[1],
    reverse=True
)[:5]

print("    Top 5 most important features:")
for feat, imp in top_features:
    print(f"      {feat:<20} : {imp:.4f}")

# ── Save model ─────────────────────────────────────────────────
joblib.dump(clf,     f"{MODEL_DIR}/classifier_rf.joblib")
joblib.dump(scaler,  f"{MODEL_DIR}/classifier_scaler.joblib")
joblib.dump(encoder, f"{MODEL_DIR}/classifier_encoder.joblib")

# Save metadata
y_pred_all = clf.predict(X_scaled)
accuracy   = (y_pred_all == y).mean()

meta = {
    "trained_at"    : pd.Timestamp.now().isoformat(),
    "classes"       : list(encoder.classes_),
    "n_classes"     : len(encoder.classes_),
    "features"      : FEATURES,
    "n_features"    : len(FEATURES),
    "n_estimators"  : 300,
    "total_windows" : len(df_all),
    "accuracy"      : round(float(accuracy), 4),
    "model_path"    : f"{MODEL_DIR}/classifier_rf.joblib",
    "scaler_path"   : f"{MODEL_DIR}/classifier_scaler.joblib",
    "encoder_path"  : f"{MODEL_DIR}/classifier_encoder.joblib",
}

with open(f"{MODEL_DIR}/classifier_meta.json", "w") as f:
    json.dump(meta, f, indent=4)

print(f"\n    Model saved  → {MODEL_DIR}/classifier_rf.joblib")
print(f"    Scaler saved → {MODEL_DIR}/classifier_scaler.joblib")
print(f"    Encoder saved→ {MODEL_DIR}/classifier_encoder.joblib")

print("\n" + "="*52)
print(" ✅ Classifier Training Complete")
print("="*52)
print(f"  Classes  : {list(encoder.classes_)}")
print(f"  Accuracy : {accuracy:.4f}")
print("="*52 + "\n")

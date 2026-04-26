"""
Week 5 — Isolation Forest Anomaly Detection Model Trainer
Trains on your collected CSV data and saves the model to disk.
"""

import pandas as pd
import numpy as np
import json, joblib, os
from sklearn.ensemble         import IsolationForest
from sklearn.preprocessing    import StandardScaler
from sklearn.metrics          import (classification_report,
                                      confusion_matrix,
                                      roc_auc_score)

# ── Paths ─────────────────────────────────────────────────────
NORMAL_CSV   = "/app/logs/training_normal.csv"
ATTACK_CSV   = "/app/logs/training_all_attacks.csv"
MODEL_DIR    = "/app/models"
MODEL_PATH   = f"{MODEL_DIR}/isolation_forest.joblib"
SCALER_PATH  = f"{MODEL_DIR}/scaler.joblib"
META_PATH    = f"{MODEL_DIR}/model_meta.json"

# ── Features used by the model (must match feature_extractor) ─
FEATURES = [
    "pps", "bps", "avg_pkt_size", "total_packets",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "syn_ratio", "synack_ratio", "rst_ratio",
    "syn_count", "ack_count", "rst_count", "fin_count",
    "unique_src_ips", "top_ip_ratio",
    "unique_dst_ports", "unique_src_ports",
    "iat_mean", "iat_std"
]

os.makedirs(MODEL_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# 1. Load Data
# ─────────────────────────────────────────────────────────────
print("\n[1] Loading training data...")

df_normal = pd.read_csv(NORMAL_CSV)
df_attack = pd.read_csv(ATTACK_CSV)

print(f"    Normal windows : {len(df_normal)}")
print(f"    Attack windows : {len(df_attack)}")

# Remove any rows where window was nearly empty (pps < 0.5)
df_normal = df_normal[df_normal["pps"] >= 0.5].copy()
df_attack = df_attack[df_attack["pps"] >= 0.5].copy()

print(f"    Normal (clean) : {len(df_normal)}")
print(f"    Attack (clean) : {len(df_attack)}")

# ─────────────────────────────────────────────────────────────
# 2. Prepare Features
# ─────────────────────────────────────────────────────────────
print("\n[2] Preparing features...")

df_all = pd.concat([df_normal, df_attack], ignore_index=True)

X      = df_all[FEATURES].fillna(0).values
y_true = [1 if lbl == "normal" else -1
          for lbl in df_all["label"]]   # Isolation Forest: 1=normal, -1=anomaly

# ─────────────────────────────────────────────────────────────
# 3. Scale Features
# ─────────────────────────────────────────────────────────────
print("[3] Scaling features (StandardScaler)...")

scaler   = StandardScaler()
X_scaled = scaler.fit_transform(X)

joblib.dump(scaler, SCALER_PATH)
print(f"    Scaler saved → {SCALER_PATH}")

# ─────────────────────────────────────────────────────────────
# 4. Train Isolation Forest
# ─────────────────────────────────────────────────────────────
print("\n[4] Training Isolation Forest...")

# contamination = fraction of training data that is attack
# We are hardcoding this to 0.08 (8%) for realistic production tuning
contamination = 0.08

print(f"    contamination  : {contamination}")
print(f"    n_estimators   : 200")
print(f"    max_samples    : auto")

model = IsolationForest(
    n_estimators  = 200,
    contamination = contamination,
    random_state  = 42,
    n_jobs        = -1
)

# Isolation Forest is unsupervised — train ONLY on normal data
X_normal_scaled = scaler.transform(
    df_normal[FEATURES].fillna(0).values
)
model.fit(X_normal_scaled)

joblib.dump(model, MODEL_PATH)
print(f"    Model saved    → {MODEL_PATH}")

# ─────────────────────────────────────────────────────────────
# 5. Evaluate on Full Dataset
# ─────────────────────────────────────────────────────────────
print("\n[5] Evaluating model...")

y_pred         = model.predict(X_scaled)       # 1=normal, -1=anomaly
anomaly_scores = model.decision_function(X_scaled)  # higher = more normal

# Convert to binary for metrics
y_binary_true  = [0 if v == 1 else 1 for v in y_true]   # 1=attack
y_binary_pred  = [0 if v == 1 else 1 for v in y_pred]

print("\n    Classification Report:")
print(classification_report(
    y_binary_true, y_binary_pred,
    target_names=["Normal", "Attack"]
))

cm = confusion_matrix(y_binary_true, y_binary_pred)
tn, fp, fn, tp = cm.ravel()

precision = tp / max(tp + fp, 1)
recall    = tp / max(tp + fn, 1)
f1        = 2 * precision * recall / max(precision + recall, 0.001)

try:
    auc = round(roc_auc_score(y_binary_true, [-s for s in anomaly_scores]), 4)
except:
    auc = "N/A"

print(f"    Confusion Matrix:")
print(f"      True  Negatives (correctly normal)  : {tn}")
print(f"      False Positives (normal→attack)     : {fp}")
print(f"      False Negatives (attack missed)     : {fn}")
print(f"      True  Positives (correctly attack)  : {tp}")
print(f"\n    Precision : {precision:.4f}")
print(f"    Recall    : {recall:.4f}")
print(f"    F1 Score  : {f1:.4f}")
print(f"    ROC-AUC   : {auc}")

# ─────────────────────────────────────────────────────────────
# 6. Save Model Metadata
# ─────────────────────────────────────────────────────────────
meta = {
    "trained_at"      : pd.Timestamp.now().isoformat(),
    "features"        : FEATURES,
    "n_features"      : len(FEATURES),
    "normal_windows"  : len(df_normal),
    "attack_windows"  : len(df_attack),
    "contamination"   : contamination,
    "precision"       : round(precision, 4),
    "recall"          : round(recall,    4),
    "f1_score"        : round(f1,        4),
    "roc_auc"         : auc,
    "true_negatives"  : int(tn),
    "false_positives" : int(fp),
    "false_negatives" : int(fn),
    "true_positives"  : int(tp),
    "model_path"      : MODEL_PATH,
    "scaler_path"     : SCALER_PATH
}

with open(META_PATH, "w") as f:
    json.dump(meta, f, indent=4)

print(f"\n    Metadata saved → {META_PATH}")

# ─────────────────────────────────────────────────────────────
# 7. Summary
# ─────────────────────────────────────────────────────────────
print("\n" + "="*52)
print(" ✅ Model Training Complete")
print("="*52)
print(f"  Model    : {MODEL_PATH}")
print(f"  Scaler   : {SCALER_PATH}")
print(f"  Metadata : {META_PATH}")
print(f"  F1 Score : {f1:.4f}")
print("="*52 + "\n")

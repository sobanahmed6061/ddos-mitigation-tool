
import pandas as pd
import numpy as np
import json, os

# ── Config ────────────────────────────────────────────────────
NORMAL_CSV   = "/app/logs/training_normal.csv"
ATTACK_CSV   = "/app/logs/training_all_attacks.csv"
OUTPUT_DIR   = "/app/models"
SEQUENCE_LEN = 10   # look back 10 windows (50 seconds of history)

FEATURES = [
    "pps", "bps", "avg_pkt_size", "total_packets",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "syn_ratio", "synack_ratio", "rst_ratio",
    "syn_count", "ack_count", "rst_count", "fin_count",
    "unique_src_ips", "top_ip_ratio",
    "unique_dst_ports", "unique_src_ports",
    "iat_mean", "iat_std"
]
# ─────────────────────────────────────────────────────────────

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Load data ─────────────────────────────────────────────────
print("[1] Loading data...")
df_normal = pd.read_csv(NORMAL_CSV)
df_attack = pd.read_csv(ATTACK_CSV)

# Clean empty windows
df_normal = df_normal[df_normal["pps"] >= 0.5].copy()
df_attack = df_attack[df_attack["pps"] >= 0.5].copy()

print(f"    Normal windows : {len(df_normal)}")
print(f"    Attack windows : {len(df_attack)}")

# ── Assign binary labels ──────────────────────────────────────
df_normal["y"] = 0   # 0 = normal
df_attack["y"] = 1   # 1 = attack

# ── Combine and extract features ─────────────────────────────
print("[2] Building sequences...")
df_all = pd.concat([df_normal, df_attack], ignore_index=True)

X_raw = df_all[FEATURES].fillna(0).values
y_raw = df_all["y"].values

# ── Normalize features ────────────────────────────────────────
from sklearn.preprocessing import MinMaxScaler
scaler_lstm = MinMaxScaler()
X_scaled    = scaler_lstm.fit_transform(X_raw)

# Save LSTM scaler separately from Isolation Forest scaler
import joblib
joblib.dump(scaler_lstm, f"{OUTPUT_DIR}/lstm_scaler.joblib")
print(f"    LSTM scaler saved → {OUTPUT_DIR}/lstm_scaler.joblib")

# ── Build sliding window sequences ────────────────────────────
# Each sequence: SEQUENCE_LEN consecutive windows → label of last window
X_seq, y_seq = [], []

for i in range(SEQUENCE_LEN, len(X_scaled)):
    X_seq.append(X_scaled[i - SEQUENCE_LEN:i])   # shape: (seq_len, n_features)
    y_seq.append(y_raw[i])                         # label of the last window

X_seq = np.array(X_seq)   # shape: (n_samples, seq_len, n_features)
y_seq = np.array(y_seq)

print(f"    Total sequences  : {len(X_seq)}")
print(f"    Sequence shape   : {X_seq.shape}")
print(f"    Normal sequences : {(y_seq == 0).sum()}")
print(f"    Attack sequences : {(y_seq == 1).sum()}")

# ── Train / validation split ──────────────────────────────────
from sklearn.model_selection import train_test_split

X_train, X_val, y_train, y_val = train_test_split(
    X_seq, y_seq,
    test_size    = 0.2,
    random_state = 42,
    stratify     = y_seq
)

print(f"\n[3] Split complete:")
print(f"    Train samples : {len(X_train)}")
print(f"    Val   samples : {len(X_val)}")

# ── Save dataset ──────────────────────────────────────────────
np.save(f"{OUTPUT_DIR}/lstm_X_train.npy", X_train)
np.save(f"{OUTPUT_DIR}/lstm_X_val.npy",   X_val)
np.save(f"{OUTPUT_DIR}/lstm_y_train.npy", y_train)
np.save(f"{OUTPUT_DIR}/lstm_y_val.npy",   y_val)

# Save metadata for trainer
meta = {
    "sequence_len" : SEQUENCE_LEN,
    "n_features"   : len(FEATURES),
    "features"     : FEATURES,
    "train_samples": int(len(X_train)),
    "val_samples"  : int(len(X_val)),
    "normal_count" : int((y_seq == 0).sum()),
    "attack_count" : int((y_seq == 1).sum()),
}
with open(f"{OUTPUT_DIR}/lstm_meta.json", "w") as f:
    json.dump(meta, f, indent=4)

print(f"\n[4] Dataset saved to {OUTPUT_DIR}/")
print(f"    lstm_X_train.npy  → {X_train.shape}")
print(f"    lstm_X_val.npy    → {X_val.shape}")
print(f"    lstm_y_train.npy  → {y_train.shape}")
print(f"    lstm_y_val.npy    → {y_val.shape}")
print(f"    lstm_meta.json    → sequence config")
print(f"\n✅ Dataset ready for LSTM training!")

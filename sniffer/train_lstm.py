
import numpy as np
import json, os

# Suppress TensorFlow info messages
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import tensorflow as tf
from tensorflow.keras.models     import Sequential
from tensorflow.keras.layers     import LSTM, Dense, Dropout, BatchNormalization
from tensorflow.keras.callbacks  import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
from sklearn.metrics             import classification_report, confusion_matrix

# ── Paths ─────────────────────────────────────────────────────
MODEL_DIR    = "/app/models"
MODEL_PATH   = f"{MODEL_DIR}/lstm_model.keras"
META_PATH    = f"{MODEL_DIR}/lstm_meta.json"
# ─────────────────────────────────────────────────────────────

# ── Load dataset ──────────────────────────────────────────────
print("[1] Loading dataset...")
X_train = np.load(f"{MODEL_DIR}/lstm_X_train.npy")
X_val   = np.load(f"{MODEL_DIR}/lstm_X_val.npy")
y_train = np.load(f"{MODEL_DIR}/lstm_y_train.npy")
y_val   = np.load(f"{MODEL_DIR}/lstm_y_val.npy")

with open(META_PATH) as f:
    meta = json.load(f)

SEQ_LEN    = meta["sequence_len"]
N_FEATURES = meta["n_features"]

print(f"    X_train : {X_train.shape}")
print(f"    X_val   : {X_val.shape}")
print(f"    Sequence length : {SEQ_LEN}")
print(f"    Features        : {N_FEATURES}")

# ── Class weights (handle imbalance) ──────────────────────────
normal_count = int((y_train == 0).sum())
attack_count = int((y_train == 1).sum())
total        = normal_count + attack_count
weight_normal = round(total / (2 * normal_count), 3)
weight_attack = round(total / (2 * attack_count), 3)
class_weight  = {0: weight_normal, 1: weight_attack}

print(f"\n    Class weights → Normal: {weight_normal} | Attack: {weight_attack}")

# ── Build LSTM model ──────────────────────────────────────────
print("\n[2] Building LSTM model...")

model = Sequential([
    # First LSTM layer — learns short-term patterns
    LSTM(
        units          = 64,
        input_shape    = (SEQ_LEN, N_FEATURES),
        return_sequences = True,    # pass sequence to next LSTM layer
        name           = "lstm_1"
    ),
    BatchNormalization(),
    Dropout(0.3),

    # Second LSTM layer — learns longer-term patterns
    LSTM(
        units          = 32,
        return_sequences = False,   # compress to single vector
        name           = "lstm_2"
    ),
    BatchNormalization(),
    Dropout(0.3),

    # Dense classification head
    Dense(16, activation="relu",    name="dense_1"),
    Dropout(0.2),
    Dense(1,  activation="sigmoid", name="output")   # binary: normal vs attack
])

model.compile(
    optimizer = tf.keras.optimizers.Adam(learning_rate=0.001),
    loss      = "binary_crossentropy",
    metrics   = ["accuracy",
                 tf.keras.metrics.Precision(name="precision"),
                 tf.keras.metrics.Recall(name="recall")]
)

model.summary()

# ── Callbacks ─────────────────────────────────────────────────
callbacks = [
    # Stop training if val_loss stops improving
    EarlyStopping(
        monitor   = "val_loss",
        patience  = 10,
        restore_best_weights = True,
        verbose   = 1
    ),

    # Save best model automatically
    ModelCheckpoint(
        filepath  = MODEL_PATH,
        monitor   = "val_loss",
        save_best_only = True,
        verbose   = 1
    ),

    # Reduce learning rate when stuck
    ReduceLROnPlateau(
        monitor  = "val_loss",
        factor   = 0.5,
        patience = 5,
        verbose  = 1
    )
]

# ── Train ─────────────────────────────────────────────────────
print("\n[3] Training LSTM...")
history = model.fit(
    X_train, y_train,
    validation_data = (X_val, y_val),
    epochs          = 60,
    batch_size      = 16,
    class_weight    = class_weight,
    callbacks       = callbacks,
    verbose         = 1
)

# ── Evaluate ──────────────────────────────────────────────────
print("\n[4] Evaluating on validation set...")
y_pred_prob = model.predict(X_val, verbose=0).flatten()
y_pred      = (y_pred_prob >= 0.5).astype(int)

print("\n    Classification Report:")
print(classification_report(y_val, y_pred, target_names=["Normal", "Attack"]))

cm          = confusion_matrix(y_val, y_pred)
tn, fp, fn, tp = cm.ravel()
precision   = tp / max(tp + fp, 1)
recall      = tp / max(tp + fn, 1)
f1          = 2 * precision * recall / max(precision + recall, 0.001)

print(f"    Confusion Matrix:")
print(f"      True  Negatives : {tn}")
print(f"      False Positives : {fp}")
print(f"      False Negatives : {fn}")
print(f"      True  Positives : {tp}")
print(f"\n    Precision : {precision:.4f}")
print(f"    Recall    : {recall:.4f}")
print(f"    F1 Score  : {f1:.4f}")

# ── Save updated metadata ──────────────────────────────────────
meta.update({
    "lstm_trained_at"  : str(np.datetime64("now")),
    "lstm_epochs_run"  : len(history.history["loss"]),
    "lstm_precision"   : round(precision, 4),
    "lstm_recall"      : round(recall,    4),
    "lstm_f1"          : round(f1,        4),
    "lstm_model_path"  : MODEL_PATH,
    "true_negatives"   : int(tn),
    "false_positives"  : int(fp),
    "false_negatives"  : int(fn),
    "true_positives"   : int(tp),
})

with open(META_PATH, "w") as f:
    json.dump(meta, f, indent=4)

# ── Summary ───────────────────────────────────────────────────
print("\n" + "="*52)
print(" ✅ LSTM Training Complete")
print("="*52)
print(f"  Model    : {MODEL_PATH}")
print(f"  Epochs   : {len(history.history['loss'])}")
print(f"  F1 Score : {f1:.4f}")
print("="*52 + "\n")

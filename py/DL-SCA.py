import numpy as np
import matplotlib.pyplot as plt
import chipwhisperer as cw
from tqdm.notebook import tqdm, trange

# 深度學習框架
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

print(f'TensorFlow version: {tf.__version__}')
print(f'GPU available: {tf.config.list_physical_devices("GPU")}')

AES_Sbox = np.array([
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
])
hw_list = np.array([bin(i).count('1') for i in range(256)])
print('S-Box 和 HW 表已載入')

trace_num = 5000   # Profiling 用，建議越多越好

project_file_name = f"traces/CWLITEARM_TINYAES128C_{trace_num}_fixedkey.cwp"
print(f'Reading {project_file_name}...')
proj = cw.open_project(project_file_name)

t_all = np.array(proj.waves)    # shape: (trace_num, trace_length)
p_all = np.array(proj.textins)  # shape: (trace_num, 16)
k_all = np.array(proj.keys)     # shape: (trace_num, 16)

num_traces, trace_length = t_all.shape
print(f'Number of traces = {num_traces}, trace length = {trace_length}')
print(f'True Key[0] = {k_all[0][0]:02X}h')

TARGET_BYTE = 0   # 可改成 0~15

# ── 計算 label ──────────────────────────────────────────────
true_key_byte = k_all[0][TARGET_BYTE]   # 真實金鑰（已知，用於訓練）
sbox_out = AES_Sbox[p_all[:, TARGET_BYTE] ^ true_key_byte]
hw_labels = hw_list[sbox_out]           # shape: (num_traces,)，值 0~8

print(f'Target Byte: {TARGET_BYTE}, True Key = {true_key_byte:02X}h')
print(f'HW label 分佈:')
for hw in range(9):
    count = np.sum(hw_labels == hw)
    bar = '█' * (count // 20)
    print(f'  HW={hw}: {count:5d} 條  {bar}')

# ── Trace 標準化（Z-score normalization）──────────────────────
# 重要！CNN 對輸入值的尺度敏感，標準化可加速收斂
t_mean = t_all.mean(axis=0)
t_std  = t_all.std(axis=0) + 1e-10
t_norm = (t_all - t_mean) / t_std

# ── 切分 Train / Validation / Attack 集 ─────────────────────
# Profiling（訓練）: 80%  |  Attack: 20%
n_train = int(num_traces * 0.8)
n_val   = int(n_train * 0.1)   # 從 train 中再切 10% 作 validation

idx = np.random.permutation(n_train)
train_idx = idx[n_val:]
val_idx   = idx[:n_val]
attack_idx = np.arange(n_train, num_traces)

X_train = t_norm[train_idx].reshape(-1, trace_length, 1)   # CNN 需要 (N, L, 1)
X_val   = t_norm[val_idx].reshape(-1, trace_length, 1)
X_atk   = t_norm[attack_idx].reshape(-1, trace_length, 1)

y_train = to_categorical(hw_labels[train_idx], num_classes=9)
y_val   = to_categorical(hw_labels[val_idx],   num_classes=9)

p_atk   = p_all[attack_idx]   # 攻擊集的明文（用於計算 Key Rank）
k_atk   = k_all[attack_idx]

print(f'\n資料集大小:')
print(f'  Train:      {X_train.shape[0]:5d} 條')
print(f'  Validation: {X_val.shape[0]:5d} 條')
print(f'  Attack:     {X_atk.shape[0]:5d} 條')
print(f'  Input shape: {X_train.shape[1:]}')

def build_cnn(input_length, n_classes=9):
    """
    建立 1D-CNN 模型用於 DL-SCA Profiling Attack
    參考: Zaid et al., TCHES 2020
    """
    inp = keras.Input(shape=(input_length, 1), name='trace_input')

    # Block 1
    x = layers.Conv1D(32, 11, padding='same', activation='selu', name='conv1')(inp)
    x = layers.BatchNormalization()(x)
    x = layers.AveragePooling1D(2, name='pool1')(x)

    # Block 2
    x = layers.Conv1D(64, 11, padding='same', activation='selu', name='conv2')(x)
    x = layers.BatchNormalization()(x)
    x = layers.AveragePooling1D(2, name='pool2')(x)

    # Block 3
    x = layers.Conv1D(128, 11, padding='same', activation='selu', name='conv3')(x)
    x = layers.BatchNormalization()(x)
    x = layers.AveragePooling1D(2, name='pool3')(x)

    # 分類頭
    x = layers.Flatten()(x)
    x = layers.Dense(256, activation='relu', name='fc1')(x)
    x = layers.Dropout(0.5)(x)
    x = layers.Dense(128, activation='relu', name='fc2')(x)
    x = layers.Dropout(0.25)(x)
    out = layers.Dense(n_classes, activation='softmax', name='output')(x)

    model = Model(inputs=inp, outputs=out, name='CNN_SCA')
    return model

model = build_cnn(trace_length)
model.summary()

EPOCHS     = 50
BATCH_SIZE = 256
LR         = 1e-3

model.compile(
    optimizer=keras.optimizers.Adam(LR),
    loss='categorical_crossentropy',
    metrics=['accuracy']
)

callbacks = [
    EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True,
                  verbose=1),
    ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5,
                      min_lr=1e-6, verbose=1),
]

print('訓練開始...')
history = model.fit(
    X_train, y_train,
    validation_data=(X_val, y_val),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    callbacks=callbacks,
    verbose=1
)
print('訓練完成！')

fig, axes = plt.subplots(1, 2, figsize=(14, 4))

axes[0].plot(history.history['loss'],     label='Train Loss',   color='steelblue')
axes[0].plot(history.history['val_loss'], label='Val Loss',     color='crimson', linestyle='--')
axes[0].set_title('Loss 曲線', fontsize=13)
axes[0].set_xlabel('Epoch')
axes[0].set_ylabel('Loss')
axes[0].legend()
axes[0].grid(True, alpha=0.3)

axes[1].plot(history.history['accuracy'],     label='Train Acc', color='steelblue')
axes[1].plot(history.history['val_accuracy'], label='Val Acc',   color='crimson', linestyle='--')
axes[1].set_title('Accuracy 曲線', fontsize=13)
axes[1].set_xlabel('Epoch')
axes[1].set_ylabel('Accuracy')
axes[1].legend()
axes[1].grid(True, alpha=0.3)

plt.suptitle(f'DL-SCA Training History — Byte {TARGET_BYTE}', fontsize=14)
plt.tight_layout()
plt.show()

# CNN 對 Attack 集的預測
print('計算 Attack 集預測...')
proba = model.predict(X_atk, batch_size=512, verbose=0)
# proba shape: (n_attack, 9)

def compute_key_rank(proba, plaintexts, true_key_byte,
                     AES_Sbox, hw_list, n_traces=None):
    """
    計算 Key Rank 隨使用 Trace 數量的變化

    回傳:
        key_ranks: shape (n_traces,) 的 Key Rank 陣列
    """
    if n_traces is None:
        n_traces = len(proba)

    scores = np.zeros(256)  # 每個金鑰假設的對數似然分數
    key_ranks = []

    for i in range(n_traces):
        p_byte = plaintexts[i, TARGET_BYTE]
        for kg in range(256):
            hw_pred = hw_list[AES_Sbox[p_byte ^ kg]]
            # 避免 log(0)：加一個很小的數
            scores[kg] += np.log(proba[i, hw_pred] + 1e-300)

        # 計算當前 Key Rank（分數由高到低排，正確金鑰在第幾位）
        rank = np.sum(scores > scores[true_key_byte])  # 有多少假設的分數比正確金鑰高
        key_ranks.append(rank + 1)  # +1 讓最好排名為 1

    return np.array(key_ranks)

true_key_byte = k_atk[0][TARGET_BYTE]
print(f'True Key Byte {TARGET_BYTE} = {true_key_byte:02X}h')

key_ranks = compute_key_rank(proba, p_atk, true_key_byte,
                              AES_Sbox, hw_list, n_traces=len(proba))

print(f'最終 Key Rank: {key_ranks[-1]}')
print(f'使用 {np.argmax(key_ranks == 1) + 1 if 1 in key_ranks else "未達到"} 條 Trace 達到 Key Rank = 1')

fig, ax = plt.subplots(figsize=(12, 5))

ax.plot(range(1, len(key_ranks)+1), key_ranks,
        color='steelblue', linewidth=1.5, label='Key Rank (DL-SCA)')
ax.axhline(y=1,   color='green',  linestyle='--', linewidth=1.5, alpha=0.8, label='Rank = 1（成功）')
ax.axhline(y=128, color='orange', linestyle=':', linewidth=1,   alpha=0.8, label='Rank = 128（隨機）')

ax.set_title(f'DL-SCA Key Rank Curve — Byte {TARGET_BYTE}
（曲線越快降到 1 = 攻擊越有效率）',
             fontsize=13)
ax.set_xlabel('Number of Attack Traces')
ax.set_ylabel('Key Rank')
ax.set_yscale('log')
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

# 找到第一次達到 Rank=1 的 Trace 數量
if 1 in key_ranks:
    first_rank1 = np.argmax(key_ranks == 1) + 1
    print(f'第 {first_rank1} 條 Trace 時 Key Rank 降至 1（攻擊成功）')
else:
    print('Attack 集 Trace 數量不足，尚未達到 Key Rank = 1，建議增加 Trace 數量')

# 用 Grad 計算哪些採樣點對預測最重要（類似 GradCAM）
import tensorflow as tf

# 建立 gradient model：輸入 → 最後一個 Conv 層輸出 + 最終輸出
grad_model = tf.keras.Model(
    inputs=model.inputs,
    outputs=[model.get_layer('conv3').output, model.output]
)

# 取第一條 Attack Trace 的梯度
sample_trace = X_atk[:1]
true_hw = hw_list[AES_Sbox[p_atk[0, TARGET_BYTE] ^ true_key_byte]]

with tf.GradientTape() as tape:
    conv_out, predictions = grad_model(sample_trace)
    loss = predictions[:, true_hw]

grads = tape.gradient(loss, conv_out)
weights = tf.reduce_mean(grads, axis=[0, 2]).numpy()       # 各 filter 的重要性
conv_out_np = conv_out[0].numpy()                          # (pooled_length, n_filters)
cam = np.dot(conv_out_np, weights)                         # CAM
cam = np.maximum(cam, 0)                                    # ReLU

# 上採樣回原始 Trace 長度
cam_up = np.interp(np.linspace(0, len(cam)-1, trace_length),
                   np.arange(len(cam)), cam)
cam_up = (cam_up - cam_up.min()) / (cam_up.max() + 1e-10)  # 正規化 0~1

fig, axes = plt.subplots(2, 1, figsize=(18, 7), sharex=True)

axes[0].plot(sample_trace[0, :, 0], color='steelblue', linewidth=0.6)
axes[0].set_title(f'Attack Trace（Byte {TARGET_BYTE}，True HW={true_hw}）')
axes[0].set_ylabel('Power (normalized)')
axes[0].grid(True, alpha=0.3)

axes[1].fill_between(range(trace_length), cam_up, color='crimson', alpha=0.6)
axes[1].set_title('CNN 關注的採樣點（愈紅 = 模型愈重視 = 洩漏越強）')
axes[1].set_xlabel('Sample Points')
axes[1].set_ylabel('Importance')
axes[1].grid(True, alpha=0.3)

plt.suptitle('DL-SCA — CNN Feature Importance（類 GradCAM）', fontsize=14)
plt.tight_layout()
plt.show()

top5 = np.argsort(cam_up)[-5:][::-1]
print('CNN 最重視的前 5 個採樣點（洩漏候選）:')
for rank, pt in enumerate(top5):
    print(f'  第 {rank+1} 名: Sample {pt:5d}  重要性={cam_up[pt]:.4f}')

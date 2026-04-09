SCOPETYPE = 'OPENADC'
PLATFORM = 'CWLITEARM'
CRYPTO_TARGET = 'TINYAES128C'
VERSION = 'HARDWARE'
SS_VER = 'SS_VER_1_1'

%run "../Setup_Scripts/Setup_Generic.ipynb"

%%bash -s "$PLATFORM" "$CRYPTO_TARGET" "$SS_VER"
cd ../../firmware/mcu/simpleserial-aes
make PLATFORM=$1 CRYPTO_TARGET=$2 SS_VER=$3

fw_path = '../../firmware/mcu/simpleserial-aes/simpleserial-aes-{}.hex'.format(PLATFORM)
cw.program_target(scope, prog, fw_path)

from tqdm.notebook import trange
import numpy as np
import time

ktp = cw.ktp.Basic()
trace_num = 2000

proj_name = f"traces/CWLITEARM_{CRYPTO_TARGET}_{trace_num}_fixedkey.cwp"
project = cw.create_project(proj_name, overwrite=True)

for i in trange(trace_num, desc='Capturing traces'):
    key, text = ktp.next()
    trace = cw.capture_trace(scope, target, text, key)
    if trace is None:
        continue
    project.traces.append(trace)

print(f'Number of samples = {scope.adc.samples}')
project.save()

scope.dis()
target.dis()

import chipwhisperer as cw
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import gaussian_kde   # 用 KDE 估計機率密度函數

# AES S-Box
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

# Hamming Weight 查表
hw_list = np.array([bin(i).count('1') for i in range(256)])
print('S-Box 和 HW 表已載入')

trace_num = 2000
project_file_name = f"traces/CWLITEARM_TINYAES128C_{trace_num}_fixedkey.cwp"
print(f'Reading {project_file_name}...')
proj = cw.open_project(project_file_name)

t = np.array(proj.waves)    # shape: (trace_num, trace_length)
p = np.array(proj.textins)  # shape: (trace_num, 16)
k = np.array(proj.keys)     # shape: (trace_num, 16)

num_traces, trace_length = t.shape
print(f'Number of traces = {num_traces}, trace length = {trace_length}')
print(f'True Key (Byte 0) = {k[0][0]:02X}h')

def mutual_information_histogram(x_vals, y_vals, bins=9):
    """
    用直方圖法估計 I(X; Y)

    參數:
        x_vals : 洩漏模型預測值，shape (N,)，值域 0~8（HW）
        y_vals : 實際 Trace 採樣值，shape (N,)
        bins   : 直方圖的 bin 數量（X 的類別數，HW 為 0~8 共 9 種）
    回傳:
        mi : 互資訊值（float）
    """
    N = len(x_vals)

    # X 的類別（HW 值 0~8）
    x_bins = np.arange(bins + 1) - 0.5  # 分割點：-0.5, 0.5, 1.5, ..., 8.5
    y_min, y_max = y_vals.min(), y_vals.max()
    y_bins = np.linspace(y_min, y_max, bins + 1)

    # 聯合分佈 P(X, Y)
    joint, _, _ = np.histogram2d(x_vals.astype(float), y_vals,
                                  bins=[x_bins, y_bins])
    joint = joint / N  # 正規化為機率

    # 邊際分佈
    px = joint.sum(axis=1)  # P(X)
    py = joint.sum(axis=0)  # P(Y)

    # 計算互資訊
    mi = 0.0
    for i in range(len(px)):
        for j in range(len(py)):
            if joint[i, j] > 0 and px[i] > 0 and py[j] > 0:
                mi += joint[i, j] * np.log2(joint[i, j] / (px[i] * py[j]))
    return mi


def mutual_information_kde(x_discrete, y_continuous, n_points=50):
    """
    用 KDE 法估計 I(X; Y)（精度較高，速度較慢）

    X 為離散（HW 0~8），Y 為連續（Trace 值）
    I(X;Y) = H(Y) - H(Y|X)
    """
    # 估計 H(Y)：整體的熵
    kde_all = gaussian_kde(y_continuous)
    y_grid = np.linspace(y_continuous.min(), y_continuous.max(), n_points)
    p_y = kde_all(y_grid)
    p_y = p_y / p_y.sum()
    H_Y = -np.sum(p_y * np.log2(p_y + 1e-300))

    # 估計 H(Y|X)：條件熵
    H_Y_given_X = 0.0
    for x_val in np.unique(x_discrete):
        idx = (x_discrete == x_val)
        p_x = idx.mean()
        if p_x == 0 or idx.sum() < 5:
            continue
        y_given_x = y_continuous[idx]
        kde_x = gaussian_kde(y_given_x)
        p_yx = kde_x(y_grid)
        p_yx = p_yx / (p_yx.sum() + 1e-300)
        h = -np.sum(p_yx * np.log2(p_yx + 1e-300))
        H_Y_given_X += p_x * h

    return H_Y - H_Y_given_X

print('互資訊估計函式已定義')

k_guess_range = np.arange(256)

# ── 加速設定：只對部分採樣點計算（可改成 None 跑全部）
SAMPLE_STEP = 10   # 每隔 10 個採樣點取一個；改成 1 = 全部計算（較慢）
sample_points = np.arange(0, trace_length, SAMPLE_STEP)
n_samples = len(sample_points)
t_sub = t[:, sample_points]   # 只取選中的採樣點

print(f'計算採樣點數: {n_samples}（原始 {trace_length} 點，間隔 {SAMPLE_STEP}）')

# MI 結果矩陣：shape = (16 bytes, 256 key guesses, n_samples)
# 為節省記憶體，只儲存最大 MI（每個採樣點的最大值）
mi_max_per_key = np.zeros((16, 256))   # 每個 byte × 每個金鑰假設，取最大 MI
Guess_Key = np.zeros(16, dtype=int)
Coef      = np.zeros(16)

print('MIA 計算開始...')
from tqdm.notebook import tqdm

for b in tqdm(range(16), desc='Byte'):
    for kg in range(256):
        # 計算此金鑰假設的洩漏模型預測（HW of SBox output）
        sbox_out = AES_Sbox[p[:, b] ^ kg]   # shape: (num_traces,)
        hw_pred  = hw_list[sbox_out]          # HW 值，shape: (num_traces,)

        # 對每個採樣點計算互資訊，取最大值
        mi_vals = np.array([
            mutual_information_histogram(hw_pred, t_sub[:, s])
            for s in range(n_samples)
        ])
        mi_max_per_key[b, kg] = mi_vals.max()

    best_kg = np.argmax(mi_max_per_key[b])
    Guess_Key[b] = best_kg
    Coef[b] = mi_max_per_key[b, best_kg]

print('\nMIA 計算完成！')
print(f'  True Key: {k[0]}')
print(f' Guess Key: {Guess_Key}')
match = np.sum(Guess_Key == k[0])
print(f' 猜中 {match}/16 個 Byte')

fig, axes = plt.subplots(4, 4, figsize=(22, 16))

for b in range(16):
    ax = axes[b // 4, b % 4]
    true_key = k[0][b]

    # 畫出所有金鑰假設的 MI 值
    ax.bar(range(256), mi_max_per_key[b], color='lightsteelblue',
           width=1.0, label='All guesses')

    # 標出正確金鑰（紅色）
    ax.bar(true_key, mi_max_per_key[b, true_key],
           color='crimson', width=2, label=f'True key={true_key:02X}h')

    # 標出猜測金鑰（藍色虛線）
    ax.axvline(x=Guess_Key[b], color='steelblue', linestyle='--',
               linewidth=1.5, label=f'Guess={Guess_Key[b]:02X}h')

    ax.set_title(f'Byte {b}  True={true_key:02X}h  Guess={Guess_Key[b]:02X}h',
                 fontsize=10,
                 color='green' if Guess_Key[b] == true_key else 'red')
    ax.set_xlabel('Key Guess')
    ax.set_ylabel('Max MI')
    ax.legend(fontsize=7)

plt.suptitle('MIA — 各 Byte 最大互資訊 vs 金鑰假設
（紅色 = 正確金鑰）',
             fontsize=14, y=1.01)
plt.tight_layout()
plt.show()

b = 0   # 觀察第 0 個 Byte

# 對 Byte 0 的正確金鑰和所有金鑰假設，計算每個採樣點的 MI
true_key_b0 = k[0][b]
mi_trace_true  = np.zeros(n_samples)
mi_trace_wrong = np.zeros((20, n_samples))  # 只取 20 個錯誤假設作代表

hw_true = hw_list[AES_Sbox[p[:, b] ^ true_key_b0]]
for s in range(n_samples):
    mi_trace_true[s] = mutual_information_histogram(hw_true, t_sub[:, s])

wrong_keys = [kg for kg in range(0, 256, 13) if kg != true_key_b0][:20]
for wi, kg in enumerate(wrong_keys):
    hw_w = hw_list[AES_Sbox[p[:, b] ^ kg]]
    for s in range(n_samples):
        mi_trace_wrong[wi, s] = mutual_information_histogram(hw_w, t_sub[:, s])

fig, ax = plt.subplots(figsize=(18, 5))
for wi in range(20):
    ax.plot(sample_points, mi_trace_wrong[wi], color='lightgray',
            linewidth=0.5, alpha=0.7)
ax.plot(sample_points, mi_trace_true, color='crimson',
        linewidth=1.5, label=f'True key = {true_key_b0:02X}h')
ax.set_title(f'MIA — Byte 0：各採樣點的互資訊
（紅色 = 正確金鑰，灰色 = 錯誤假設）',
             fontsize=13)
ax.set_xlabel('Sample Point')
ax.set_ylabel('Mutual Information (bits)')
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

peak_pt = sample_points[np.argmax(mi_trace_true)]
print(f'Byte 0 MI 峰值位置: Sample {peak_pt}，MI = {mi_trace_true.max():.5f} bits')

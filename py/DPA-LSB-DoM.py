#!/usr/bin/env python
# coding: utf-8

# ## 設定參數

# In[ ]:


SCOPETYPE = 'OPENADC'
PLATFORM = 'CWLITEARM'
CRYPTO_TARGET = 'TINYAES128C'
VERSION = 'HARDWARE'
SS_VER = 'SS_VER_1_1'

# ## 抓板子

# In[ ]:


%run "../Setup_Scripts/Setup_Generic.ipynb"

# ## 編AES-128的程式

# In[ ]:


%%bash -s "$PLATFORM" "$CRYPTO_TARGET" "$SS_VER"
cd ../../firmware/mcu/simpleserial-aes
make PLATFORM=$1 CRYPTO_TARGET=$2 SS_VER=$3

# ## 將AES燒到板子上

# In[ ]:


fw_path = '../../firmware/mcu/simpleserial-aes/simpleserial-aes-{}.hex'.format(PLATFORM)
cw.program_target(scope, prog, fw_path)

# ## 錄Trace、印出隨機產生的明文

# In[ ]:


#Capture Traces
from tqdm.notebook import trange
import numpy as np
import time

ktp = cw.ktp.Basic()

traces = []
trace_num = 2000  # Number of traces# Number of traces
# scope.adc.samples = 24400

proj_name = f"traces/CWLITEARM_{CRYPTO_TARGET}_{trace_num}_fixedkey.cwp"    # 專案檔檔名，可以知道板子 加密算法 trace數 固定金鑰
project = cw.create_project(proj_name, overwrite=True)

for i in trange(trace_num, desc='Capturing traces'):
    # ktp.next()是產生下一組隨機的key和明文
    # key是固定的、明文是隨機的
    key, text = ktp.next()  # manual creation of a key, text pair can be substituted here
    print(i, text)             # 確認下面的輸出的明文是相同的
    trace = cw.capture_trace(scope, target, text, key)                   # 抓trace
    if trace is None:
        continue
    project.traces.append(trace)                                         # 加到trace物件內
    
# 抓了300條Trace，每條Trace共有5000個點
print(f'Number of samples = {scope.adc.samples}')
project.save()

# ## 與板子斷開連線

# In[ ]:


scope.dis()
target.dis()

# ## import套件

# In[2]:


import chipwhisperer as cw
import numpy as np   # python中拿來做向量運算的套件，numpy是用C語言寫的，所以計算上會快很多
import matplotlib.pyplot as plt

# ## 對應表

# In[6]:


# The AES SBox that we will use to generate our labels
AES_Sbox = np.array([
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            ])


# ## Load Traces

# In[7]:


SCOPETYPE = 'OPENADC'
PLATFORM = 'CWLITEARM'
CRYPTO_TARGET = 'TINYAES128C'
VERSION = 'HARDWARE'
SS_VER = 'SS_VER_1_1'

trace_num = 2000  # Number of traces

project_file_name = f"traces/CWLITEARM_{CRYPTO_TARGET}_{trace_num}_fixedkey.cwp"   # 剛剛創的專案的路徑
print(f'Reading {project_file_name}...')
proj = cw.open_project(project_file_name)                                       # 取得專案

t = np.array(proj.waves)                                                        # 取得trace
p = np.array(proj.textins)                                                      # 取得明文
k = np.array(proj.keys)                                                         # 取得key
c = np.array(proj.textouts)                                                     # 取得輸出值
num_traces = t.shape[0]
trace_length = t.shape[1]
print(f'Number of traces = {num_traces}, trace length = {trace_length}')

# ## 印出明文、金鑰

# In[8]:


print("Plaintext: ")
print("Size=", p.shape, sep="")
print(p)
print("")

print("Key: ")
print("Size=", k.shape, sep="")
print(k)

# ## 計算相關係數(R)

# In[31]:


k_guess = np.array(range(256))              # 建一個 0~255 的 numpy array，用於將明文與所有金鑰可能作xor運算
sum_0 = np.zeros((16, 256, trace_length))
sum_1 = np.zeros((16, 256, trace_length))
n_0 = np.zeros((16, 256))
n_1 = np.zeros((16, 256))
r = np.zeros((16, 256, trace_length))       # 存每一條明文和 Traces 所計算出來的相關係數，且有 16Bytes

Guess_Key = np.zeros((16), dtype=int)       # 存相關係數矩陣中有最大值的 byte 值
Point = np.zeros((16), dtype=int)           # 存
Coef = np.zeros((16))

max_coef_per_row = np.zeros((trace_num, 16, 256))   # 存每條trace中相關係數矩陣每列最大的相關係數值; 共 16bytes 故16張圖g

print("計算開始")
for i in range(trace_num):
    for b in range(16):                             # 共 16 bytes
        h = 0x01 & AES_Sbox[p[i][b] ^ k_guess]    # h矩陣為每一條明文的 byte 與所有金鑰可能做xor, sbox轉換, 取LSB後的結果; 大小為(1, 256)

        for j in range(256):
            if h[j] == 0:
                sum_0[b, j] += t[i]
                n_0[b, j] += 1
            else:
                sum_1[b, j] += t[i]
                n_1[b, j] += 1

        mean_0 = sum_0[b] / (n_0[b][:, None] + 1e-40)
        mean_1 = sum_1[b] / (n_1[b][:, None] + 1e-40)
        r[b] = mean_0 - mean_1
        max_coef = np.max(np.abs(r[b]))                           # 取得每一 byte 中最大的相關係數數值
        Coef[b] = max_coef                                        # 存每一 byte 的最大相關係數值
        key_byte, point = np.where(np.abs(r[b]) == max_coef)      # 取得每一 byte 中有最大相關係數數值所在列、所在行
        Guess_Key[b] = key_byte[0]                                # 存每一 byte 存到猜測的金鑰中
        Point[b] = point[0]
        max_coef_per_row[i][b] = np.max(np.abs(r[b]), axis=1)     # 找每個相關係數矩陣中，每列的最大值(共256個)
        
    np.set_printoptions(precision=5, linewidth=np.inf)            # 設定小數點位數、不自動換行
    print("Trace{:04}:".format(i + 1))
    print("  True Key:", end="")
    print(k[0])
    print(" Guess Key:", end="")
    print(Guess_Key)
    print("Coeffcient:", end="")
    print(Coef)
    print("   Samples:", end="")
    print(Point)
    print("")
print("計算結束")

# ## 圖1

# In[27]:


fig, axes = plt.subplots(4, 4, figsize=(24, 24))                   # 設定排版

for b in range(16):
    axes[b // 4, b % 4].set_title("Byte{}".format(b))
    axes[b // 4, b % 4].set_ylim(-0.01, 0.01)
    axes[b // 4, b % 4].set_xlabel('Samples')
    axes[b // 4, b % 4].set_ylabel('Correlation')
    axes[b // 4, b % 4].plot(r[b, :, :].T)

# ## 印出所有Byte中有最大相關係數的附近幾列

# In[28]:


fig, axes = plt.subplots(16, 4, figsize=(24, 96))                   # 設定排版

print("Guess Key:", end="")
print(Guess_Key)

for b in range(16):
    for j in range(4):
        axes[b, j % 4].set_title("Key Hypothesis = {}".format(Guess_Key[b]+j%4-2))
        axes[b, j % 4].set_ylim(-0.01, 0.01)
        axes[b, j % 4].set_xlabel('Samples')
        axes[b, j % 4].set_ylabel('Correlation')
        axes[b, j % 4].plot(r[b, Guess_Key[b]+j%4-2:Guess_Key[b]+j%4-1, :].T)

# In[ ]:




# In[ ]:




# In[ ]:




# In[ ]:




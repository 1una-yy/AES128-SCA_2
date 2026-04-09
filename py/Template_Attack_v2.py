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

# ## 錄Trace(Template)、印出隨機產生的明文、隨機的金鑰

# In[ ]:


#Capture Traces
from tqdm.notebook import trange
import numpy as np
import time

ktp = cw.ktp.Basic()
ktp.fixed_key = False

traces = []
trace_num = 10000  # Number of traces

proj_name = f"traces/CWLITEARM_{CRYPTO_TARGET}_{trace_num}_unfixedkey.cwp"    # 專案檔檔名，可以知道板子 加密算法 trace數 固定金鑰
project = cw.create_project(proj_name, overwrite=True)

for i in trange(trace_num, desc='Capturing traces'):
    # ktp.next()是產生下一組隨機的key和明文
    # key是固定的、明文是隨機的
    key, text = ktp.next()  # manual creation of a key, text pair can be substituted here
    print(i, text)             # 確認下面的輸出的明文是不同的
    print(i, key)
    trace = cw.capture_trace(scope, target, text, key)                   # 抓trace
    if trace is None:
        continue
    project.traces.append(trace)                                         # 加到trace物件內
    
# 抓了300條Trace，每條Trace共有5000個點
print(f'Number of samples = {scope.adc.samples}')
project.save()

# ## 錄Traces(Target)、印出隨機產生的明文、固定的金鑰

# In[ ]:


#Capture Traces
from tqdm.notebook import trange
import numpy as np
import time

ktp = cw.ktp.Basic()

traces = []
trace_num = 100  # Number of traces

proj_name = f"traces/CWLITEARM_{CRYPTO_TARGET}_{trace_num}_fixedkey.cwp"    # 專案檔檔名，可以知道板子 加密算法 trace數 固定金鑰
project = cw.create_project(proj_name, overwrite=True)

for i in trange(trace_num, desc='Capturing traces'):
    key, text = ktp.next()  # manual creation of a key, text pair can be substituted here
    print(i, text)
    print(i, key)
    trace = cw.capture_trace(scope, target, text, key)                   # 抓trace
    if trace is None:
        continue
    project.traces.append(trace)                                         # 加到trace物件內
    
print(f'Number of samples = {scope.adc.samples}')
project.save()

# ## 與板子斷開連線

# In[ ]:


scope.dis()
target.dis()

# ## ====================這是分隔線====================

# ## import套件

# In[1]:


import chipwhisperer as cw
import numpy as np   # python中拿來做向量運算的套件，numpy是用C語言寫的，所以計算上會快很多
import matplotlib.pyplot as plt
from scipy.stats import multivariate_normal

# ## 對應表

# In[2]:


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
# The Hamming weight list of each byte value
hw_list = np.array([
            0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
            1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
            1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
            2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
            1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
            2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
            2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
            3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
            ])
# Number of combinations for each Hamming weight
# 不同的HW共有多少種，例如 HW=0的只有一種
hw_combinations = np.array([1, 8, 28, 56, 70, 56, 28, 8, 1])

# ## Load Traces(Template)

# In[3]:


SCOPETYPE = 'OPENADC'
PLATFORM = 'CWLITEARM'
CRYPTO_TARGET = 'TINYAES128C'
VERSION = 'HARDWARE'
SS_VER = 'SS_VER_1_1'

template_trace_num = 10000  # Number of traces

template_project_file_name = f"traces/CWLITEARM_{CRYPTO_TARGET}_{template_trace_num}_unfixedkey.cwp"   # 剛剛創的專案的路徑
print(f'Reading {template_project_file_name}...')
template_proj = cw.open_project(template_project_file_name)                                       # 取得專案

template_t = np.array(template_proj.waves)                                                        # 取得trace
template_p = np.array(template_proj.textins)                                                      # 取得明文
template_k = np.array(template_proj.keys)                                                         # 取得key
template_c = np.array(template_proj.textouts)                                                     # 取得輸出值
template_num_traces = template_t.shape[0]
template_trace_length = template_t.shape[1]
print(f'Number of traces = {template_num_traces}, trace length = {template_trace_length}')

# ## 印出明文、金鑰(Template)

# In[4]:


print("Plaintext: ")
print("Size=", template_p.shape, sep="")
print(template_p)
print("")

print("Key: ")
print("Size=", template_k.shape, sep="")
print(template_k)

# ## 明文 xor 金鑰(Template)

# In[5]:


template_x = template_p ^ template_k
print("明文 xor 金鑰: ")
print("Size=", template_x.shape, sep="")
print(template_x)

# ## Sbox轉換(Template)

# In[6]:


template_y = AES_Sbox[template_x]
print("S-Box轉換後: ")
print("Size=", template_y.shape, sep="")
print(template_y)

# ## Hamming Weight轉換(Template)

# In[7]:


template_h = hw_list[template_y]
print("Hamming Weight轉換後: ")
print("Size=", template_h.shape, sep="")
print(template_h)

# ## 計算分群後平均的變異數(分母)、分群後變異數的平均(分母)

# In[8]:


print("設定參數")
var = np.zeros((16, template_trace_length))    # 存16bytes分群後平均的變異數
avg = np.zeros((16, template_trace_length))    # 存16bytes分群後變異數的平均
SNR = np.zeros((16, template_trace_length))    # 存16bytes的SNR
avg_diff_HW = np.zeros((16, 9, template_trace_length)) # 存16bytes的九群的平均
var_diff_HW = np.zeros((16, 9, template_trace_length)) # 存16bytes的九群的變異數
count = np.zeros((16, 9), dtype=int)                    # 存 HW=0 ~ HW=8各有多少個

print("計算開始")
for b in range(16):                          # 16 bytes做16次
    t_sum = np.zeros((9, template_trace_length))      # 分成9群
    t2_sum = np.zeros((9, template_trace_length))
    avg_t = np.zeros((9, template_trace_length))
    avg2_t = np.zeros((9, template_trace_length))
    var_t = np.zeros((9, template_trace_length))
    
    for j in range(template_trace_num):               # 對每一行(每一byte)的不同 HW 做分群
        target = template_h[j, b]                     # 取得第j行(每一byte)所有HW，target會得到介於0到8的數值
        t_sum[target] += template_t[j]                # 將第j條波形的5000個樣本點加總到對應的 target index 那格中
        t2_sum[target] += template_t[j] ** 2
        count[b][target] += 1                # 九格分別代表 HW 0~8 共有多少條trace的
        
    prob = count[b] / template_trace_num              # 每一Byte"實際上"出現的機率
    
    for j in range(9):
        avg_t[j] = t_sum[j] / count[b][j]                     # 計算分群的平均
        var_t[j] = t2_sum[j] / count[b][j] - avg_t[j] ** 2    # 計算分群的變異數
    
    # 下面計算分群後平均的變異數; 平方的平均 - 平均的平方
    var[b] = sum((avg_t ** 2) * prob.reshape(9, 1)) - sum(avg_t * prob.reshape(9, 1)) ** 2 + 1e-40
    # 下面計算分群後變異數的平均; 
    avg[b] = sum(var_t * prob.reshape(9, 1)) + 1e-40# 計算分群變異數的平均
    avg_diff_HW[b] = avg_t
    var_diff_HW[b] = var_t

print("計算結束")

# ## 印出 16 Bytes中 HW=0 ~ HW=8 分別有幾條Traces

# In[9]:


for b in range(16):
    print("第{}Byte".format(b))
    for j in range(9):
        print("HW={}, 共有{:5d}條Traces.".format(j, count[b][j]))

# ## 印出分群後平均的變異數

# In[10]:


print("分群後平均的變異數:")
print("Size=", var.shape, sep="")
for j in range(16):
    print("第 {:2} byte ".format(j), end="")
    print(var[j])

# ## 印出分群後變異數的平均

# In[11]:


print("分群後變異數的平均:")
print("Size=", avg.shape, sep="")
for j in range(16):
    print("第 {:2} byte ".format(j), end="")
    print(avg[j])

# ## 印出 16 Bytes的SNR

# In[12]:


SNR = var / avg
print("SNR:")
print("Size=", SNR.shape, sep="")
for j in range(16):
    print("第 {:2} byte ".format(j), end="")
    print(SNR[j])

# ## 畫出 16 Bytes的SNR

# In[13]:


print(SNR.shape)

fig, axes = plt.subplots(4, 4, figsize=(16, 16))                   # 設定排版

for b in range(16):
    value = max(SNR[b])                                            # 存每一byte中最大的SNR值
    index = np.argmax(SNR[b])                                      # 存每一byte中最大的SNR值所在位置
    axes[b // 4, b % 4].text(index, value, '[{}, {}]'.format(index, value))
    axes[b // 4, b % 4].plot(SNR[b])
    axes[b // 4, b % 4].set_title("Byte{}".format(b))

# ## 畫出 16 Bytes的九群的平均波形

# In[14]:


fig, axes = plt.subplots(4, 4, figsize=(16, 16))                   # 設定排版

for b in range(16):
    index = np.argmax(SNR[b])                                      # 存每一byte中最大的SNR值所在位置
    axes[b // 4, b % 4].plot(avg_diff_HW[b, :9, index-5:index+6].T)
    axes[b // 4, b % 4].set_title("Byte{}".format(b))

# ## 畫出 16 Bytes的九群的變異數波形

# In[15]:


fig, axes = plt.subplots(4, 4, figsize=(16, 16))                   # 設定排版

for b in range(16):
    index = np.argmax(SNR[b])                                      # 存每一byte中最大的SNR值所在位置
    axes[b // 4, b % 4].set_title("Byte{}".format(b))
    axes[b // 4, b % 4].plot(var_diff_HW[b, :9, index-5:index+6].T)

# ## Load Traces(Target)

# In[16]:


SCOPETYPE = 'OPENADC'
PLATFORM = 'CWLITEARM'
CRYPTO_TARGET = 'TINYAES128C'
VERSION = 'HARDWARE'
SS_VER = 'SS_VER_1_1'

target_trace_num = 100  # Number of traces

target_project_file_name = f"traces/CWLITEARM_{CRYPTO_TARGET}_{target_trace_num}_fixedkey.cwp"   # 剛剛創的專案的路徑
print(f'Reading {target_project_file_name}...')
target_proj = cw.open_project(target_project_file_name)                                       # 取得專案

target_t = np.array(target_proj.waves)                                                        # 取得trace
target_p = np.array(target_proj.textins)                                                      # 取得明文
target_k = np.array(target_proj.keys)                                                         # 取得key
target_c = np.array(target_proj.textouts)                                                     # 取得輸出值
target_num_traces = target_t.shape[0]
target_trace_length = target_t.shape[1]
print(f'Number of traces = {target_num_traces}, trace length = {target_trace_length}')

# ## 印出明文、金鑰(Target)

# In[17]:


print("Plaintext: ")
print("Size=", target_p.shape, sep="")
print(target_p)
print("")

print("Key[0]: ")
print("Size=", target_k.shape, sep="")
print(target_k[0])

# ## 明文 xor 金鑰(Target)

# In[18]:


target_x = target_p ^ target_k
print("明文 xor 金鑰: ")
print("Size=", target_x.shape, sep="")
print(target_x)

# ## Sbox轉換(Target)

# In[19]:


target_y = AES_Sbox[target_x]
print("S-Box轉換後: ")
print("Size=", target_y.shape, sep="")
print(target_y)

# ## Hamming Weight轉換(Target)

# In[20]:


target_h = hw_list[target_y]
print("Hamming Weight轉換後: ")
print("Size=", target_h.shape, sep="")
print(target_h)

# ## 做Template Attack(用Hamming Weight分成8群)

# In[21]:


poi_num = 10

poi_index = np.argsort(SNR, axis=1)[:, -poi_num:]
Guess_Key = np.zeros((16), dtype=int)

mean = np.zeros((16, 9, poi_num))
covariance = np.zeros((16, 9, poi_num, poi_num))

print("計算開始")
for b in range(16):
    
    template_poi = template_t[:, poi_index[b]]
   
    for i in range(9):
        g = template_poi[template_h[:, b]==i, :]
        mean[b, i] = np.mean(g, axis=0)
        covariance[b, i] = np.cov(g, rowvar=False)
    
hw_log_prob = np.zeros(9)
key_log_prob = np.zeros((16, 256))

for i in range(100):
    for b in range(16):
        target_poi = target_t[:, poi_index[b]]
        for j in range(9):
            hw_log_prob[j] = np.log(multivariate_normal.pdf(target_poi[i], mean=mean[b, j], cov=covariance[b, j], allow_singular=True)/hw_combinations[j]+1e-40)

        key_log_prob[b] += hw_log_prob[hw_list[AES_Sbox[np.arange(256)^target_p[i, b]]]]
        Guess_Key[b] = np.argmax(key_log_prob[b])

    print(Guess_Key)

print("計算結束")

# ## 做Template Attack(用中間值分256群)

# In[22]:


poi_num = 10

poi_index = np.argsort(SNR, axis=1)[:, -poi_num:]
Guess_Key = np.zeros((16), dtype=int)

mean = np.zeros((16, 256, poi_num))
covariance = np.zeros((16, 256, poi_num, poi_num))

print("計算開始")
for b in range(16):
    template_poi = template_t[:, poi_index[b]]
   
    for i in range(256):
        g = template_poi[template_y[:, b]==i, :]
        mean[b, i] = np.mean(g, axis=0)
        covariance[b, i] = np.cov(g, rowvar=False)
    
temp = np.zeros(256)
key_log_prob = np.zeros((16, 256))

for i in range(100):
    for b in range(16):
        target_poi = target_t[:, poi_index[b]]
        for j in range(256):
            temp[j] = np.log(multivariate_normal.pdf(target_poi[i], mean=mean[b, j], cov=covariance[b, j], allow_singular=True)+1e-40)

        key_log_prob[b] += temp[AES_Sbox[np.arange(256)^target_p[i, b]]]
        Guess_Key[b] = np.argmax(key_log_prob[b])

    print(Guess_Key)

print("計算結束")

# In[ ]:




# In[ ]:




# In[ ]:




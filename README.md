# AES-128 Side-Channel Attack

AES-128 旁路攻擊實作，包含 CPA、DPA、Template Attack 等方法，並提供 REST API 供前端串接。

---

## 專案結構

```
aes128/
├── py/                        # 攻擊程式（.py 版本）
│   ├── CPA.py                 # Correlation Power Analysis
│   ├── DPA-LSB-DoM.py         # DPA - Difference of Means
│   ├── DPA-LSB-PCC.py         # DPA - Pearson Correlation Coefficient
│   ├── Template_Attack_v1.py  # Template Attack v1
│   ├── Template_Attack_v2.py  # Template Attack v2
│   ├── SNR.py                 # Signal-to-Noise Ratio 分析
│   ├── MIA.py                 # Mutual Information Analysis
│   └── DL-SCA.py              # Deep Learning SCA
├── api/                       # FastAPI 後端（供前端串接）
│   ├── main.py                # API 主程式
│   ├── cpa_attack.py          # CPA 攻擊核心邏輯
│   └── requirements.txt       # 套件需求
├── traces/                    # 功耗波形資料（.cwp 專案）
└── *.ipynb                    # 原始 Jupyter Notebook
```

---

## API 啟動方式

### 1. 安裝套件

```bash
cd api
pip install -r requirements.txt
```

### 2. 啟動 API 伺服器

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3. 查看 API 文件

啟動後打開瀏覽器：`http://localhost:8000/docs`

---

## API 串接說明（給前端）

### POST `/attack/cpa` — 執行 CPA 攻擊

**上傳兩個 `.npy` 檔案：**

| 欄位 | 說明 | 格式 |
|------|------|------|
| `traces_file` | 功耗波形 | `.npy`，shape: `(num_traces, trace_length)` |
| `plaintexts_file` | 對應明文 | `.npy`，shape: `(num_traces, 16)`，dtype: `uint8` |

**回傳 JSON：**

```json
{
  "key": "2b7e151628aed2a6abf7158809cf4f3c",
  "key_bytes": [43, 126, 21, 22, 40, 174, 210, 166, ...],
  "num_traces": 2000,
  "trace_length": 24400,
  "plot_base64": "<base64 PNG 圖片>"
}
```

**前端顯示圖表範例：**

```html
<img src="data:image/png;base64,{{ plot_base64 }}" />
```

**JavaScript 呼叫範例：**

```javascript
const formData = new FormData();
formData.append("traces_file", tracesFile);       // .npy 檔案
formData.append("plaintexts_file", plaintextsFile); // .npy 檔案

const res = await fetch("http://localhost:8000/attack/cpa", {
  method: "POST",
  body: formData
});

const { key, key_bytes, plot_base64 } = await res.json();
console.log("猜測金鑰：", key);
document.getElementById("plot").src = `data:image/png;base64,${plot_base64}`;
```

---

## 攻擊方法說明

| 方法 | 檔案 | 說明 |
|------|------|------|
| CPA | `py/CPA.py` | 相關功耗分析，使用 Pearson 相關係數 |
| DPA (DoM) | `py/DPA-LSB-DoM.py` | 差分功耗分析，Difference of Means |
| DPA (PCC) | `py/DPA-LSB-PCC.py` | 差分功耗分析，Pearson Correlation |
| Template Attack | `py/Template_Attack_v1/v2.py` | 模板攻擊 |
| SNR | `py/SNR.py` | 訊雜比分析 |
| MIA | `py/MIA.py` | 互資訊分析 |
| DL-SCA | `py/DL-SCA.py` | 深度學習旁路攻擊 |

---

## 環境需求

- Python 3.8+
- chipwhisperer
- numpy
- matplotlib
- fastapi
- uvicorn

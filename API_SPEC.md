# SCA Attack API 串接規格

> 本文件給負責**前端**與 **AI 模組**閱讀。
> 你們不需要看攻擊程式碼，只需按照本文件的輸入輸出格式串接即可。

---

## 一、啟動方式

```bash
cd api/
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

啟動後可在瀏覽器開啟互動文件：**http://localhost:8000/docs**

---

## 二、整體架構

```
使用者（瀏覽器）
    ↓ 上傳 traces / plaintexts
Django 後端
    ↓ 呼叫攻擊 API（本文件）
    ↓ [可選] 呼叫 AI 前處理 API（陳泓諺的模組）
攻擊 API（本文件）
    ↓ 回傳金鑰 + 圖表
Django 後端
    ↓ 顯示結果
使用者（瀏覽器）
```

---

## 三、API 一覽

| 方法 | 路徑 | 說明 |
|------|------|------|
| `GET` | `/algorithms` | 取得目前支援的演算法清單 |
| `POST` | `/attack/{algorithm_id}` | 執行指定演算法的攻擊 |
| `GET` | `/health` | 確認 API 是否運行中 |

---

## 四、API 詳細說明

---

### `GET /algorithms` — 取得演算法清單

前端用這支 API 動態產生演算法下拉選單，**不需要寫死演算法名稱**。
攻擊之後加新演算法，前端會自動出現。

**回傳範例：**
```json
{
  "algorithms": [
    {
      "id": "cpa",
      "display_name": "Correlation Power Analysis (CPA)",
      "description": "使用 Pearson 相關係數，對 AES SBox 輸出的 Hamming Weight 建模，進行金鑰恢復。"
    },
    {
      "id": "dpa",
      "display_name": "Differential Power Analysis (DPA)",
      "description": "..."
    }
  ]
}
```

---

### `POST /attack/{algorithm_id}` — 執行攻擊

`algorithm_id` 從 `/algorithms` 取得的 `id` 欄位填入，例如 `cpa`、`dpa`。

**請求格式：** `multipart/form-data`

| 欄位名稱 | 必填 | 說明 |
|----------|------|------|
| `traces_file` | ✅ 必填 | 功耗波形，`.npy` 格式，shape `(N, trace_length)`，dtype `float32` |
| `plaintexts_file` | ✅ 必填 | 明文，`.npy` 格式，shape `(N, 16)`，dtype `uint8` |
| `preprocessed_traces_file` | ⬜ 選填 | AI 模組輸出的前處理 traces（見第五節） |

**回傳格式（JSON）：**

```json
{
  "algorithm":    "cpa",
  "key_hex":      "2b7e151628aed2a6abf7158809cf4f3c",
  "key_bytes":    [43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60],
  "num_traces":   2000,
  "trace_length": 24400,
  "plot_base64":  "iVBORw0KGgoAAAANSUhEUgAA..."
}
```

| 欄位 | 說明 |
|------|------|
| `key_hex` | 猜測的 AES 金鑰（32 字元 hex 字串） |
| `key_bytes` | 同上，以十進位陣列表示 |
| `num_traces` | 本次攻擊使用的 trace 數量 |
| `trace_length` | 每條 trace 的採樣點數 |
| `plot_base64` | 相關係數圖，base64 編碼的 PNG |

**顯示圖表：**
```html
<img src="data:image/png;base64,{{ result.plot_base64 }}" />
```

---

## 五、與 AI 模組整合

### AI 模組的職責

AI 模組負責對 traces 進行：
1. 去噪（Denoising）
2. 時序對齊（Alignment）
3. 洩漏點定位（CNN/MLP 找出最有用的採樣區段）

### AI 模組輸出格式

> 請按照以下格式輸出，攻擊模組才能直接使用。

```python
import numpy as np

# preprocessed_traces：shape 與原始 traces 相同，或是裁切過的子區段
# dtype: float32 或 float64
preprocessed_traces = your_model.process(raw_traces)  # shape: (N, trace_length)

# 儲存為 .npy 供上傳
np.save("preprocessed_traces.npy", preprocessed_traces)
```

### Django 的整合流程

```python
# views.py 範例
import requests
import numpy as np
import io

def run_attack(request):
    traces_file      = request.FILES['traces']
    plaintexts_file  = request.FILES['plaintexts']
    algorithm        = request.POST.get('algorithm', 'cpa')

    files = {
        'traces_file':     ('traces.npy', traces_file.read(), 'application/octet-stream'),
        'plaintexts_file': ('plaintexts.npy', plaintexts_file.read(), 'application/octet-stream'),
    }

    # 如果有 AI 前處理結果，加入 preprocessed_traces_file
    if 'preprocessed_traces' in request.FILES:
        files['preprocessed_traces_file'] = (
            'preprocessed.npy',
            request.FILES['preprocessed_traces'].read(),
            'application/octet-stream'
        )

    response = requests.post(
        f"http://localhost:8000/attack/{algorithm}",
        files=files
    )
    result = response.json()

    return render(request, 'result.html', {'result': result})
```

---

## 六、.npy 檔案格式說明

### 從 ChipWhisperer 專案匯出

```python
import chipwhisperer as cw
import numpy as np

proj = cw.open_project("traces/CWLITEARM_TINYAES128C_2000_fixedkey.cwp")
traces     = np.array(proj.waves)    # shape: (2000, 24400), dtype: float32
plaintexts = np.array(proj.textins)  # shape: (2000, 16),    dtype: uint8

np.save("traces.npy", traces)
np.save("plaintexts.npy", plaintexts)
```

### 從 Django 表單接收並轉換

```python
import numpy as np
import io

def load_npy_from_upload(uploaded_file):
    return np.load(io.BytesIO(uploaded_file.read()))
```

---

## 七、錯誤代碼

| HTTP 狀態碼 | 說明 |
|-------------|------|
| `200` | 成功 |
| `400` | 輸入格式錯誤（檔案格式、shape 不符等） |
| `404` | 找不到指定的演算法（`algorithm_id` 填錯） |
| `500` | 攻擊執行過程發生內部錯誤 |

錯誤回傳格式：
```json
{
  "detail": "錯誤說明文字"
}
```

---

## 八、未來新增演算法（陳昱廷）

新增 DPA 攻擊為例，只需：

1. 在 `api/attacks/` 新增 `dpa.py`
2. 繼承 `BaseAttack`，實作 `run()` 方法
3. 在檔案結尾呼叫 `registry.register(DPAAttack())`

**API 路徑自動變成** `POST /attack/dpa`，前端不需要修改任何程式碼。

```python
# api/attacks/dpa.py 範例骨架
from attack_base import BaseAttack, AttackInput, AttackResult, registry

class DPAAttack(BaseAttack):
    name         = "dpa"
    display_name = "Differential Power Analysis (DPA)"
    description  = "..."

    def run(self, data: AttackInput) -> AttackResult:
        # 在這裡實作 DPA 攻擊邏輯
        ...
        return AttackResult(
            algorithm    = self.name,
            key_hex      = ...,
            key_bytes    = ...,
            num_traces   = ...,
            trace_length = ...,
            plot_base64  = ...,
        )

registry.register(DPAAttack())
```

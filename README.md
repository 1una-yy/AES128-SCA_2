# AES-128 Side-Channel Attack Platform

AES-128 旁通道攻擊實作，提供 CPA、DPA、MIA、Template Attack 等攻擊模組，並以 REST API 供前端與 AI 模組串接。

---

## 專案結構

```
aes128/
├── py/                        # 攻擊程式原始碼（.py 版本）
│   ├── CPA.py
│   ├── DPA-LSB-DoM.py
│   ├── DPA-LSB-PCC.py
│   ├── Template_Attack_v1.py
│   ├── Template_Attack_v2.py
│   ├── SNR.py
│   ├── MIA.py
│   └── DL-SCA.py
├── api/                       # FastAPI 後端（供前端與 AI 模組串接）
│   ├── main.py                # API 主程式
│   ├── attack_base.py         # 攻擊模組介面與 Registry
│   ├── attacks/               # 各攻擊演算法模組
│   │   ├── cpa.py
│   │   ├── dpa_dom.py
│   │   ├── dpa_pcc.py
│   │   ├── mia.py
│   │   └── template.py
│   └── requirements.txt
├── API_SPEC.md                # 串接規格文件（給前端與 AI 模組閱讀）
└── traces/                    # 功耗波形資料（不推上 Git）
```

---

## API 啟動方式

```bash
cd api
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

啟動後開啟 **http://localhost:8000/docs** 查看互動式 API 文件。

---

## 串接說明（給前端 / AI 模組）

詳細規格請參考 **[API_SPEC.md](./API_SPEC.md)**，包含：
- 所有 API endpoint 說明
- 前端呼叫範例（Django views.py）
- AI 模組輸出格式規範
- 支援的輸入檔案格式

### 快速總覽

| 方法 | 路徑 | 說明 |
|------|------|------|
| `GET` | `/algorithms` | 取得支援的演算法清單（動態，新增演算法後自動更新） |
| `POST` | `/attack/{algorithm_id}` | 執行攻擊，回傳金鑰與圖表 |

### 支援上傳格式

| 格式 | 說明 |
|------|------|
| `.npy` | NumPy array |
| `.csv` | 逗號分隔，每行一條 trace |
| `.h5` / `.hdf5` | HDF5，dataset 名稱為 `traces` / `plaintexts` |
| `.trs` | Riscure Inspector trace 格式 |

---

## 新增演算法（攻擊模組開發者）

在 `api/attacks/` 新增 `.py`，繼承 `BaseAttack`，API 自動支援：

```python
# api/attacks/my_attack.py
from attack_base import BaseAttack, AttackInput, AttackResult, registry

class MyAttack(BaseAttack):
    name         = "my_attack"
    display_name = "My New Attack"
    description  = "說明"

    def run(self, data: AttackInput) -> AttackResult:
        # 攻擊邏輯
        ...

registry.register(MyAttack())
```

---

## 環境需求

- Python 3.8+
- fastapi, uvicorn, numpy, matplotlib, scipy
- chipwhisperer（量測硬體時使用，API 運行不需要）

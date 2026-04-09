"""
main.py
AES-128 Side-Channel Attack API
啟動方式：uvicorn main:app --reload --host 0.0.0.0 --port 8000
API 文件：http://localhost:8000/docs

架構說明：
  - 所有攻擊演算法放在 attacks/ 資料夾
  - 新增演算法只需在 attacks/ 新增 .py 並繼承 BaseAttack，API 自動支援
  - 前端只需呼叫 POST /attack/{algorithm_id}，不需要因為加新演算法而改程式碼
"""

import importlib
import pkgutil
import os
import sys
import io

import numpy as np
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# 確保 attacks/ 資料夾可以被 import
sys.path.insert(0, os.path.dirname(__file__))

from attack_base import registry, AttackInput
from trace_loader import load_traces, load_plaintexts

# ── 自動載入 attacks/ 資料夾下所有演算法模組 ──────────────────────────
import attacks
for _, module_name, _ in pkgutil.iter_modules(attacks.__path__):
    importlib.import_module(f"attacks.{module_name}")
# ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SCA Attack API",
    description="""
## 旁通道攻擊 API

**使用流程：**
1. `GET /algorithms` — 查詢目前支援的攻擊演算法清單
2. `POST /attack/{algorithm_id}` — 上傳 traces 與 plaintexts，執行攻擊

**支援上傳格式：** `.npy` / `.csv` / `.h5` / `.hdf5` / `.trs`

**與 AI 模組整合：**
- AI 模組負責前處理，輸出前處理後的 traces 檔案
- 前端上傳時加上 `preprocessed_traces_file` 欄位即可啟用

**新增演算法：**
- 在 `attacks/` 資料夾新增 .py 檔，繼承 `BaseAttack`，API 自動支援
    """,
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # 正式環境請填前端網址
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── 共用工具 ──────────────────────────────────────────────────────────

async def read_upload(file: UploadFile, field_name: str, is_plaintext: bool = False) -> np.ndarray:
    """讀取上傳檔案，自動依副檔名解析格式（npy/csv/h5/trs）"""
    try:
        content = await file.read()
        if is_plaintext:
            return load_plaintexts(content, file.filename or "file.npy")
        else:
            return load_traces(content, file.filename or "file.npy")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"{field_name} 解析失敗：{e}")


# ── Endpoints ─────────────────────────────────────────────────────────

@app.get("/", summary="狀態確認")
def root():
    return {"status": "ok", "message": "SCA Attack API 運行中，請前往 /docs 查看文件"}


@app.get(
    "/algorithms",
    summary="取得支援的攻擊演算法清單",
    description="前端用來動態產生演算法選單，不需要寫死演算法名稱。",
)
def list_algorithms():
    return {"algorithms": registry.list_all()}


@app.post(
    "/attack/{algorithm_id}",
    summary="執行攻擊",
    description="""
執行指定演算法的旁通道攻擊。

**必填欄位：**
- `traces_file`：功耗波形 `.npy`，shape `(N, trace_length)`，dtype `float32/float64`
- `plaintexts_file`：明文 `.npy`，shape `(N, 16)`，dtype `uint8`

**選填欄位（AI 前處理整合）：**
- `preprocessed_traces_file`：AI 模組輸出的對齊/去噪後 traces，格式同 traces_file
  - 若提供，攻擊將使用此 traces 而非原始 traces
  - 不提供則直接用原始 traces

**回傳：**
```json
{
  "algorithm":    "cpa",
  "key_hex":      "2b7e151628aed2a6abf7158809cf4f3c",
  "key_bytes":    [43, 126, ...],
  "num_traces":   2000,
  "trace_length": 24400,
  "plot_base64":  "<base64 PNG>"
}
```

前端顯示圖表：`<img src="data:image/png;base64,{plot_base64}" />`
""",
)
async def run_attack(
    algorithm_id: str,
    traces_file: UploadFile = File(..., description="功耗波形 .npy"),
    plaintexts_file: UploadFile = File(..., description="明文 .npy，shape (N, 16)"),
    preprocessed_traces_file: UploadFile = File(None, description="[選填] AI 前處理後的 traces .npy"),
    template_traces_file: UploadFile = File(None, description="[Template Attack 專用] 模板 traces .npy"),
    template_plaintexts_file: UploadFile = File(None, description="[Template Attack 專用] 模板明文 .npy"),
    template_keys_file: UploadFile = File(None, description="[Template Attack 專用] 模板金鑰 .npy"),
):
    # 查詢演算法
    attack = registry.get(algorithm_id)
    if attack is None:
        available = [a["id"] for a in registry.list_all()]
        raise HTTPException(
            status_code=404,
            detail=f"找不到演算法 '{algorithm_id}'，目前支援：{available}"
        )

    # 讀取必填檔案（支援 npy / csv / h5 / trs）
    traces     = await read_upload(traces_file, "traces_file")
    plaintexts = await read_upload(plaintexts_file, "plaintexts_file", is_plaintext=True)

    # 選填：AI 前處理
    preprocessed = None
    if preprocessed_traces_file is not None:
        preprocessed = await read_upload(preprocessed_traces_file, "preprocessed_traces_file")

    # 選填：Template Attack 模板資料
    tmpl_traces     = None
    tmpl_plaintexts = None
    tmpl_keys       = None
    if template_traces_file is not None:
        tmpl_traces     = await read_upload(template_traces_file, "template_traces_file")
    if template_plaintexts_file is not None:
        tmpl_plaintexts = await read_upload(template_plaintexts_file, "template_plaintexts_file", is_plaintext=True)
    if template_keys_file is not None:
        tmpl_keys       = await read_upload(template_keys_file, "template_keys_file", is_plaintext=True)

    # 組裝輸入並執行攻擊
    data = AttackInput(
        traces=traces,
        plaintexts=plaintexts,
        preprocessed_traces=preprocessed,
        template_traces=tmpl_traces,
        template_plaintexts=tmpl_plaintexts,
        template_keys=tmpl_keys,
    )

    try:
        result = attack.run(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"攻擊執行失敗：{e}")

    return JSONResponse({
        "algorithm":    result.algorithm,
        "key_hex":      result.key_hex,
        "key_bytes":    result.key_bytes,
        "num_traces":   result.num_traces,
        "trace_length": result.trace_length,
        "plot_base64":  result.plot_base64,
        **result.extra,
    })


@app.get("/health", summary="Health check")
def health():
    return {"status": "ok"}

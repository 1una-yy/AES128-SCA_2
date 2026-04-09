"""
main.py
AES-128 Side-Channel Attack API
啟動方式：uvicorn main:app --reload --host 0.0.0.0 --port 8000
API 文件：http://localhost:8000/docs
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
import io

from cpa_attack import cpa_attack, generate_correlation_plot

app = FastAPI(
    title="AES-128 CPA Attack API",
    description="上傳功耗波形與明文，執行 CPA 攻擊並回傳金鑰與相關係數圖",
    version="1.0.0"
)

# 允許前端跨網域呼叫（CORS）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 正式環境請改成前端的網址
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "AES-128 CPA Attack API 啟動成功，請前往 /docs 查看 API 文件"}


@app.post(
    "/attack/cpa",
    summary="執行 CPA 攻擊",
    description="""
上傳兩個 `.npy` 檔案：
- **traces_file**：功耗波形，shape = (num_traces, trace_length)，dtype = float32 或 float64
- **plaintexts_file**：對應明文，shape = (num_traces, 16)，dtype = uint8

回傳：
- **key**：16 bytes 的猜測金鑰（hex 字串）
- **key_bytes**：list of int，每個 byte 的十進位值
- **plot_base64**：相關係數圖（base64 編碼 PNG）
"""
)
async def run_cpa_attack(
    traces_file: UploadFile = File(..., description="traces .npy 檔案"),
    plaintexts_file: UploadFile = File(..., description="plaintexts .npy 檔案")
):
    # 讀取並解析 traces
    try:
        traces_bytes = await traces_file.read()
        traces = np.load(io.BytesIO(traces_bytes))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"traces 檔案解析失敗：{e}")

    # 讀取並解析 plaintexts
    try:
        pt_bytes = await plaintexts_file.read()
        plaintexts = np.load(io.BytesIO(pt_bytes))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"plaintexts 檔案解析失敗：{e}")

    # 格式驗證
    if traces.ndim != 2:
        raise HTTPException(status_code=400, detail=f"traces 應為 2D array，實際為 {traces.ndim}D")
    if plaintexts.ndim != 2 or plaintexts.shape[1] != 16:
        raise HTTPException(status_code=400, detail=f"plaintexts 應為 (N, 16)，實際為 {plaintexts.shape}")
    if traces.shape[0] != plaintexts.shape[0]:
        raise HTTPException(
            status_code=400,
            detail=f"traces ({traces.shape[0]}) 與 plaintexts ({plaintexts.shape[0]}) 筆數不一致"
        )

    # 執行攻擊
    try:
        guess_key, r = cpa_attack(traces, plaintexts)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"攻擊執行失敗：{e}")

    # 產生圖表
    try:
        plot_b64 = generate_correlation_plot(r)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"圖表產生失敗：{e}")

    # 回傳結果
    key_bytes_val = bytes(guess_key)
    return JSONResponse({
        "key": key_bytes_val.hex(),           # e.g. "2b7e151628aed2a6..."
        "key_bytes": guess_key,               # e.g. [43, 126, 21, ...]
        "num_traces": int(traces.shape[0]),
        "trace_length": int(traces.shape[1]),
        "plot_base64": plot_b64               # 前端用 <img src="data:image/png;base64,...">
    })


@app.get("/health")
def health_check():
    return {"status": "ok"}

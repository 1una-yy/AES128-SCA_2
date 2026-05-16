"""
trace_loader.py
統一處理多種 trace 格式的載入器。
支援：.npy / .csv / .h5(.hdf5) / .trs
"""

import numpy as np
import io
from fastapi import HTTPException


def load_traces(file_bytes: bytes, filename: str) -> np.ndarray:
    """
    根據副檔名自動解析 traces 檔案，回傳 np.ndarray。

    Parameters:
        file_bytes : 上傳的原始 bytes
        filename   : 原始檔名（用來判斷格式）

    Returns:
        np.ndarray，shape (num_traces, trace_length)
    """
    ext = filename.rsplit(".", 1)[-1].lower()

    if ext == "npy":
        return _load_npy(file_bytes)
    elif ext == "csv":
        return _load_csv(file_bytes)
    elif ext in ("h5", "hdf5"):
        return _load_h5(file_bytes)
    elif ext == "trs":
        return _load_trs(file_bytes)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"不支援的格式：.{ext}，請上傳 .npy / .csv / .h5 / .hdf5 / .trs"
        )


def load_plaintexts(file_bytes: bytes, filename: str) -> np.ndarray:
    """
    載入明文檔案，支援 .npy / .csv / .h5(.hdf5)。
    回傳 np.ndarray，shape (num_traces, 16)，dtype uint8。
    """
    ext = filename.rsplit(".", 1)[-1].lower()

    if ext == "npy":
        arr = np.load(io.BytesIO(file_bytes))
    elif ext == "csv":
        arr = np.loadtxt(io.StringIO(file_bytes.decode("utf-8")),
                         delimiter=",", dtype=np.uint8)
    elif ext in ("h5", "hdf5"):
        arr = _load_plaintexts_h5(file_bytes)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"明文檔案不支援 .{ext}，請上傳 .npy / .csv / .h5"
        )

    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    return arr.astype(np.uint8)


def _load_plaintexts_h5(data: bytes) -> np.ndarray:
    try:
        import h5py, tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".h5", delete=False) as f:
            f.write(data)
            tmp_path = f.name
        try:
            with h5py.File(tmp_path, "r") as hf:
                arr = _find_plaintexts_in_h5(hf)
        finally:
            os.unlink(tmp_path)
        return arr
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f".h5 明文解析失敗：{e}")


# ── 各格式解析實作 ──────────────────────────────────────────


def _load_npy(data: bytes) -> np.ndarray:
    try:
        arr = np.load(io.BytesIO(data))
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return arr.astype(np.float32)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f".npy 解析失敗：{e}")


def _load_csv(data: bytes) -> np.ndarray:
    """每行一條 trace，欄位以逗號分隔。"""
    try:
        arr = np.loadtxt(io.StringIO(data.decode("utf-8")),
                         delimiter=",", dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return arr
    except Exception as e:
        raise HTTPException(status_code=400, detail=f".csv 解析失敗：{e}")


def _load_h5(data: bytes) -> np.ndarray:
    """
    HDF5 格式，自動尋找 traces dataset。
    支援一般格式（key: traces/power_traces/data/X）與
    ASCAD 巢狀格式（Attack_traces/traces、Profiling_traces/traces）。
    """
    try:
        import h5py, tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".h5", delete=False) as f:
            f.write(data)
            tmp_path = f.name
        try:
            with h5py.File(tmp_path, "r") as hf:
                arr = _find_traces_in_h5(hf)
        finally:
            os.unlink(tmp_path)

        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return arr
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f".h5 解析失敗：{e}")


def _find_traces_in_h5(hf) -> np.ndarray:
    """在 HDF5 檔案中尋找 traces，支援一般與 ASCAD 巢狀結構。"""
    import h5py

    # ASCAD 格式：優先用 Attack_traces，其次 Profiling_traces
    for group in ("Attack_traces", "Profiling_traces"):
        if group in hf and "traces" in hf[group]:
            return np.array(hf[group]["traces"], dtype=np.float32)

    # 一般格式：根目錄找常見 key
    for key in ("traces", "power_traces", "data", "X"):
        if key in hf:
            return np.array(hf[key], dtype=np.float32)

    raise HTTPException(
        status_code=400,
        detail=f".h5 找不到 traces dataset，現有 keys：{list(hf.keys())}"
    )


def _find_plaintexts_in_h5(hf) -> np.ndarray:
    """在 HDF5 檔案中尋找明文，支援 ASCAD metadata 巢狀結構。"""
    # ASCAD 格式：Attack_traces/metadata/plaintext 或 Profiling_traces/metadata/plaintext
    for group in ("Attack_traces", "Profiling_traces"):
        if group in hf:
            meta = hf[group].get("metadata")
            if meta is not None:
                for key in ("plaintext", "plaintexts", "text"):
                    if key in meta:
                        return np.array(meta[key], dtype=np.uint8)

    # 一般格式：根目錄
    for key in ("plaintexts", "plaintext", "text"):
        if key in hf:
            return np.array(hf[key], dtype=np.uint8)

    raise HTTPException(
        status_code=400,
        detail=f".h5 找不到明文 dataset，現有 keys：{list(hf.keys())}"
    )


def _load_trs(data: bytes) -> np.ndarray:
    """
    Riscure .trs 格式簡易解析器。
    格式：header tags（TLV）+ raw trace data（float32 / int16）
    """
    try:
        buf = io.BytesIO(data)

        # 解析 header tags
        num_traces   = 0
        num_samples  = 0
        sample_coding = 0x14  # 預設：float32

        while True:
            tag = buf.read(1)
            if not tag:
                break
            tag = tag[0]
            if tag == 0x5F:  # 結束 header
                break

            length_byte = buf.read(1)[0]
            if length_byte & 0x80:
                n_len = length_byte & 0x7F
                length = int.from_bytes(buf.read(n_len), "little")
            else:
                length = length_byte

            value = buf.read(length)

            if tag == 0x41:   # NT：trace 數量
                num_traces = int.from_bytes(value, "little")
            elif tag == 0x42: # NS：每條 trace 的採樣點數
                num_samples = int.from_bytes(value, "little")
            elif tag == 0x44: # SC：sample coding
                sample_coding = value[0]

        if num_traces == 0 or num_samples == 0:
            raise HTTPException(status_code=400, detail=".trs header 解析失敗，找不到 trace 數量或採樣點數")

        # 判斷 dtype
        if sample_coding == 0x14:
            dtype, itemsize = np.float32, 4
        elif sample_coding == 0x12:
            dtype, itemsize = np.int16, 2
        elif sample_coding == 0x11:
            dtype, itemsize = np.int8, 1
        else:
            dtype, itemsize = np.float32, 4

        raw = np.frombuffer(buf.read(), dtype=dtype)
        # .trs 每條 trace 可能帶 crypto data，只取 sample 部分
        stride = len(raw) // num_traces
        traces = np.array([raw[i * stride: i * stride + num_samples]
                           for i in range(num_traces)], dtype=np.float32)
        return traces

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f".trs 解析失敗：{e}")

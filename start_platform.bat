@echo off
chcp 65001 >nul
title SCA Platform Launcher

echo ========================================
echo   AES-128 SCA Platform 啟動中...
echo ========================================
echo.

REM 切換到 api 目錄
cd /d "%~dp0api"

REM 檢查 Python 是否安裝
python --version >nul 2>&1
if errorlevel 1 (
    echo [錯誤] 找不到 Python，請先安裝 Python 3.8+
    pause
    exit /b 1
)

REM 安裝相依套件（如尚未安裝）
echo [1/3] 檢查 / 安裝相依套件...
python -m pip install -q -r requirements.txt

REM 在新視窗啟動 FastAPI 伺服器
echo [2/3] 啟動 FastAPI 後端 (port 8000)...
start "SCA FastAPI Backend" cmd /k "cd /d "%~dp0api" && python -m uvicorn main:app --host 0.0.0.0 --port 8000"

REM 等待 server 起來
echo [3/3] 等待伺服器啟動 (約 5 秒)...
timeout /t 5 /nobreak >nul

REM 開啟 platform.html
echo.
echo ✓ 啟動完成！正在開啟 platform.html ...
start "" "%~dp0platform.html"

echo.
echo ========================================
echo   後端：http://localhost:8000
echo   API 文件：http://localhost:8000/docs
echo   網頁：已在預設瀏覽器開啟
echo ========================================
echo.
echo 關閉本視窗不會關閉伺服器。
echo 要停止伺服器，請關閉 "SCA FastAPI Backend" 視窗。
echo.
pause

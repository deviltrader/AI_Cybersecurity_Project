@echo off
title SentinelAI - Cybersecurity Log Monitoring
cd /d "%~dp0"

echo ==========================================
echo   SentinelAI - Starting Application
echo ==========================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found.
    echo Please install Python 3 from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Installing/checking required packages...
python -m pip install -r requirements.txt

echo.
echo Starting SentinelAI...
python -m streamlit run app.py
pause

@echo off
cd /d "%~dp0dashboard"

start http://127.0.0.1:5000

REM Use virtual environment in dashboard\venv if present, otherwise use system Python
if exist "%~dp0dashboard\venv\Scripts\python.exe" (
	"%~dp0dashboard\venv\Scripts\python.exe" app.py
) else (
	python app.py
)

pause

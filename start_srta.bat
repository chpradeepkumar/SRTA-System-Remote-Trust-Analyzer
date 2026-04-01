@echo off
cd /d "%~dp0dashboard"

start http://127.0.0.1:5000


"C:\Users\hp\AppData\Local\Programs\Python\Python312\python.exe" app.py


pause

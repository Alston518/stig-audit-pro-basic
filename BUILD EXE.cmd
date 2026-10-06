@echo off
cd /d "%~dp0"
py -3.12 -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
py -3.12 -m PyInstaller --noconfirm "STIG Audit Basic.spec"
pause

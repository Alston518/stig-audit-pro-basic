@echo off
cd /d "%~dp0"
py -3.12 -m pip install --require-hashes -r requirements.lock
if errorlevel 1 exit /b 1
py -3.12 -m pip install --require-hashes -r requirements-tools.lock
if errorlevel 1 exit /b 1
py -3.12 -m PyInstaller --noconfirm --clean --distpath "%~dp0..\..\STIG_Basic_Next_Build" --workpath "%TEMP%\stig-basic-build" "STIG Audit Basic.spec"
if errorlevel 1 exit /b 1
py -3.12 scripts\check_basic_bundle.py "%TEMP%\stig-basic-build"
if errorlevel 1 exit /b 1
copy /y "BUILD_INFO.txt" "%~dp0..\..\STIG_Basic_Next_Build\STIG Audit Basic\BUILD_INFO.txt" >nul
if errorlevel 1 exit /b 1
pause

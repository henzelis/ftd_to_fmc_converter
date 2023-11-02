@echo off
REM Check if Python is installed
python --version > nul 2>&1
if %errorlevel% neq 0 (
    REM Download and install Python
    powershell -Command "Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe -OutFile python-3.10.0-amd64.exe"
    python-3.10.0-amd64.exe /quiet InstallAllUsers=1 PrependPath=1
    del python-3.10.0-amd64.exe
)

REM Install required Python modules
python -m pip install -r requirements.txt

REM Run configuration generation script
python ftd_to_fmc_convert.py

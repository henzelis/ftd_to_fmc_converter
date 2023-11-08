@echo off
echo Installing and configuring the FTD to FMC converter...

REM Check if Python is installed
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not found. Downloading and installing Python...
    REM Download and install Python
    powershell -Command "(New-Object System.Net.WebClient).DownloadFile('https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe', 'python-3.12.0-amd64.exe')"
    python-3.12.0-amd64.exe /quiet InstallAllUsers=1 PrependPath=1
    del python-3.12.0-amd64.exe
)

REM Set the full path to Python and the virtual environment
set PYTHON_PATH="C:\Program Files\Python312\python.exe"
set VENV_PATH=%cd%\venv

echo Python installation complete.

REM Check if the virtual environment already exists
if not exist %VENV_PATH% (
    echo Creating a virtual environment...
    REM Create virtual environment
    %PYTHON_PATH% -m venv %VENV_PATH%
    echo Virtual environment created.
)

echo Activating the virtual environment...
REM Activate the virtual environment
call %VENV_PATH%\Scripts\activate

echo Installing required Python modules...
REM Install required Python modules
%PYTHON_PATH% -m pip install -r requirements.txt
echo Required Python modules installed.

echo Running the configuration generation script...
REM Run the configuration generation script
%PYTHON_PATH% ftd_to_fmc_convert.py
echo Configuration generation script completed.

echo Deactivating the virtual environment...
REM Deactivate the virtual environment
call %VENV_PATH%\Scripts\deactivate
echo Virtual environment deactivated.

echo FTD to FMC converter setup and configuration completed.

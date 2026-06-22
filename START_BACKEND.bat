@echo off
echo ========================================
echo Sentinel AI - Backend Startup Script
echo ========================================
echo.

REM Check if Python is installed
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    pause
    exit /b 1
)

echo [OK] Python is installed
python --version
echo.

REM Check if we're in the right directory
if not exist "app\main.py" (
    echo [ERROR] Please run this script from the project root directory
    echo Current directory: %CD%
    pause
    exit /b 1
)

echo [OK] Project structure verified
echo.

REM Check if virtual environment exists (optional)
if exist "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
    echo.
)

REM Check if dependencies are installed
python -c "import fastapi" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] FastAPI not found. Installing dependencies...
    echo.
    pip install -r requirements.txt
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
    echo.
    echo [OK] Dependencies installed successfully
    echo.
) else (
    echo [OK] Dependencies already installed
    echo.
)

REM Start the backend server
echo ========================================
echo Starting FastAPI backend server...
echo ========================================
echo.
echo Backend will be available at: http://localhost:8000
echo API docs available at: http://localhost:8000/docs
echo.
echo Press Ctrl+C to stop the server
echo.
echo [INFO] Starting Ghidra MCP Bridge on port 8089...
start "Sentinel AI - Ghidra MCP" cmd /k "python ghidra_mcp_server.py"
echo.

python -m uvicorn app.main:app --reload

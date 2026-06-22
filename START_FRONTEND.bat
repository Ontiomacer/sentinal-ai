@echo off
echo ========================================
echo Sentinel AI - Frontend Startup Script
echo ========================================
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed!
    echo.
    echo Please install Node.js from: https://nodejs.org/
    echo.
    pause
    exit /b 1
)

echo [OK] Node.js is installed
node --version
npm --version
echo.

REM Check if we're in the right directory
if not exist "frontend\package.json" (
    echo [ERROR] Please run this script from the project root directory
    echo Current directory: %CD%
    pause
    exit /b 1
)

echo [OK] Project structure verified
echo.

REM Navigate to frontend directory
cd frontend

REM Check if node_modules exists
if not exist "node_modules" (
    echo [INFO] Dependencies not installed. Installing now...
    echo This may take 2-3 minutes...
    echo.
    call npm install
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

REM Check if .env exists
if not exist ".env" (
    echo [INFO] Creating .env file from template...
    copy .env.example .env >nul
    echo [OK] .env file created
    echo.
) else (
    echo [OK] .env file exists
    echo.
)

REM Start the development server
echo ========================================
echo Starting Vite development server...
echo ========================================
echo.
echo Frontend will be available at: http://localhost:5173/
echo.
echo Press Ctrl+C to stop the server
echo.

call npm run dev

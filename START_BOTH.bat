@echo off
echo ========================================
echo Sentinel AI - Full Stack Startup
echo ========================================
echo.
echo This will start both backend and frontend servers
echo in separate windows.
echo.
echo Backend: http://localhost:8000
echo Frontend: http://localhost:5173
echo.
echo Press any key to continue...
pause >nul

REM Start backend in new window
echo Starting backend server...
start "Sentinel AI - Backend" cmd /k "START_BACKEND.bat"

REM Wait a moment for backend to initialize
timeout /t 3 /nobreak >nul

REM Start frontend in new window
echo Starting frontend server...
start "Sentinel AI - Frontend" cmd /k "START_FRONTEND.bat"

echo.
echo ========================================
echo Both servers are starting...
echo ========================================
echo.
echo Backend: http://localhost:8000
echo Frontend: http://localhost:5173
echo.
echo Two new windows have been opened.
echo Close those windows to stop the servers.
echo.
echo You can close this window now.
echo.
pause

@echo off
REM Ghidra Installation Script for Windows
REM This script downloads and installs Ghidra for the Neural Lab

echo ========================================
echo Ghidra Installation for Neural Lab
echo ========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: Not running as administrator
    echo Some operations may fail
    echo.
)

REM Set installation directory
set INSTALL_DIR=C:\Tools\ghidra
set GHIDRA_VERSION=11.0.1
set GHIDRA_DATE=20240130
set GHIDRA_ZIP=ghidra_%GHIDRA_VERSION%_PUBLIC_%GHIDRA_DATE%.zip
set DOWNLOAD_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_%GHIDRA_VERSION%_build/%GHIDRA_ZIP%

echo Installation Directory: %INSTALL_DIR%
echo Ghidra Version: %GHIDRA_VERSION%
echo.

REM Check if Java is installed
echo [1/6] Checking Java installation...
java -version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Java is not installed
    echo Ghidra requires Java JDK 17 or later
    echo.
    echo Please install Java from:
    echo https://adoptium.net/temurin/releases/
    echo.
    pause
    exit /b 1
)

java -version 2>&1 | findstr /i "version" | findstr /i "17\|18\|19\|20\|21" >nul
if %errorLevel% neq 0 (
    echo WARNING: Java version may be incompatible
    echo Ghidra requires Java 17 or later
    echo.
)

echo Java is installed
echo.

REM Create installation directory
echo [2/6] Creating installation directory...
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo Created %INSTALL_DIR%
) else (
    echo Directory already exists
)
echo.

REM Check if Ghidra is already installed
if exist "%INSTALL_DIR%\ghidra_%GHIDRA_VERSION%_PUBLIC" (
    echo Ghidra %GHIDRA_VERSION% is already installed
    echo Location: %INSTALL_DIR%\ghidra_%GHIDRA_VERSION%_PUBLIC
    echo.
    set /p REINSTALL="Do you want to reinstall? (y/n): "
    if /i not "%REINSTALL%"=="y" (
        echo Skipping installation
        goto :configure
    )
    echo Removing existing installation...
    rmdir /s /q "%INSTALL_DIR%\ghidra_%GHIDRA_VERSION%_PUBLIC"
)

REM Download Ghidra
echo [3/6] Downloading Ghidra %GHIDRA_VERSION%...
echo This may take several minutes (Ghidra is ~500MB)
echo.

cd /d "%INSTALL_DIR%"

REM Use PowerShell to download
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%GHIDRA_ZIP%' -UseBasicParsing}"

if %errorLevel% neq 0 (
    echo ERROR: Failed to download Ghidra
    echo.
    echo Please download manually from:
    echo https://github.com/NationalSecurityAgency/ghidra/releases
    echo.
    echo Extract to: %INSTALL_DIR%
    echo.
    pause
    exit /b 1
)

echo Download complete
echo.

REM Extract Ghidra
echo [4/6] Extracting Ghidra...
powershell -Command "& {Expand-Archive -Path '%GHIDRA_ZIP%' -DestinationPath '%INSTALL_DIR%' -Force}"

if %errorLevel% neq 0 (
    echo ERROR: Failed to extract Ghidra
    pause
    exit /b 1
)

echo Extraction complete
echo.

REM Clean up zip file
echo [5/6] Cleaning up...
del "%GHIDRA_ZIP%"
echo.

:configure
REM Configure environment
echo [6/6] Configuring environment...

set GHIDRA_INSTALL=%INSTALL_DIR%\ghidra_%GHIDRA_VERSION%_PUBLIC

REM Add to system PATH (requires admin)
echo Adding Ghidra to PATH...
setx GHIDRA_INSTALL_DIR "%GHIDRA_INSTALL%" /M >nul 2>&1
if %errorLevel% equ 0 (
    echo Added GHIDRA_INSTALL_DIR environment variable
) else (
    echo WARNING: Could not set system environment variable
    echo Run as administrator to set system-wide PATH
)

REM Add to user PATH
setx GHIDRA_INSTALL_DIR "%GHIDRA_INSTALL%" >nul 2>&1
echo.

REM Update .env file
echo Updating .env configuration...
cd /d "%~dp0"

if exist ".env" (
    findstr /C:"GHIDRA_INSTALL_DIR" .env >nul
    if %errorLevel% neq 0 (
        echo GHIDRA_INSTALL_DIR=%GHIDRA_INSTALL% >> .env
        echo Added GHIDRA_INSTALL_DIR to .env
    ) else (
        echo GHIDRA_INSTALL_DIR already configured in .env
    )
) else (
    echo GHIDRA_INSTALL_DIR=%GHIDRA_INSTALL% > .env
    echo Created .env with GHIDRA_INSTALL_DIR
)
echo.

REM Verify installation
echo ========================================
echo Verifying Installation
echo ========================================
echo.

if exist "%GHIDRA_INSTALL%\support\analyzeHeadless.bat" (
    echo [OK] Ghidra installed successfully
    echo Location: %GHIDRA_INSTALL%
    echo.
    echo analyzeHeadless: %GHIDRA_INSTALL%\support\analyzeHeadless.bat
    echo.
) else (
    echo [ERROR] Installation verification failed
    echo analyzeHeadless.bat not found
    echo.
    pause
    exit /b 1
)

REM Test Ghidra
echo Testing Ghidra...
"%GHIDRA_INSTALL%\support\analyzeHeadless.bat" -help >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Ghidra is functional
) else (
    echo [WARNING] Ghidra test failed
    echo This may be normal - Ghidra will be tested during first use
)
echo.

echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo Ghidra has been installed to:
echo %GHIDRA_INSTALL%
echo.
echo The Neural Lab will automatically detect Ghidra
echo.
echo To use Ghidra manually:
echo 1. Run: %GHIDRA_INSTALL%\ghidraRun.bat
echo 2. Or use headless: %GHIDRA_INSTALL%\support\analyzeHeadless.bat
echo.
echo Next steps:
echo 1. Restart your terminal/IDE to load new environment variables
echo 2. Start the backend: python -m uvicorn app.main:app --reload
echo 3. Upload an APK and run Neural Lab analysis
echo.
pause

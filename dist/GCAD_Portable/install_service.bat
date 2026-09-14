@echo off
setlocal
title GCAD - Windows NT Service Installer

echo =======================================================
echo   GCAD (Galoisconnection Antivirus ^& Defense)
echo   Windows NT Service Installer
echo =======================================================
echo.

:: Check Administrator Privileges
net session >nul 2>&1
if errorlevel 1 (
    echo [!] Error: Administrator privileges required.
    echo     Please right-click this script and select "Run as Administrator".
    echo.
    pause
    exit /b 1
)

set "GCAD_BIN=%~dp0gcad.exe"
if not exist "%GCAD_BIN%" (
    echo [!] Error: Executable '%GCAD_BIN%' not found.
    pause
    exit /b 1
)

echo [*] Installing GCAD background service: %GCAD_BIN%
"%GCAD_BIN%" --service-install
if errorlevel 1 (
    echo [!] Failed to install service.
    pause
    exit /b 1
)

echo [*] Starting GCAD background service...
"%GCAD_BIN%" --service-start
if errorlevel 1 (
    echo [!] Warning during service start. Check Windows Services console.
) else (
    echo [+] GCAD service installed and started successfully!
    echo     Telemetry will stream to GUI via Named Pipe IPC.
)

echo.
pause

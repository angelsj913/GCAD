@echo off
setlocal
title GCAD - Windows NT Service Uninstaller

echo =======================================================
echo   GCAD (Galoisconnection Antivirus ^& Defense)
echo   Windows NT Service Safe Uninstaller
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

echo [*] Stopping GCAD background service...
"%GCAD_BIN%" --service-stop >nul 2>&1

echo [*] Removing GCAD background service...
"%GCAD_BIN%" --service-remove
if errorlevel 1 (
    echo [!] Failed to remove service.
    pause
    exit /b 1
)

echo [+] GCAD service removed safely.
echo.
pause

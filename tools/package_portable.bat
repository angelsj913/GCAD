@echo off
setlocal
title GCAD - USB Portable Bundling Tool

echo =======================================================
echo   GCAD (Galoisconnection Antivirus ^& Defense)
echo   USB Portable Package Generator
echo =======================================================
echo.

set "ROOT_DIR=%~dp0.."
set "BUILD_DIR=%ROOT_DIR%\build-make"
set "DIST_DIR=%ROOT_DIR%\dist\GCAD_Portable"
set "BIN_SRC=%BUILD_DIR%\bin\gcad.exe"

if not exist "%BIN_SRC%" (
    echo [*] Binary missing, running cmake build...
    cmake --build "%BUILD_DIR%" --config Release --target gcad
    if errorlevel 1 (
        echo [!] Build failed.
        exit /b 1
    )
)

if not exist "%DIST_DIR%" (
    mkdir "%DIST_DIR%"
)

echo [*] Copying gcad.exe to portable directory...
copy /y "%BIN_SRC%" "%DIST_DIR%\gcad.exe" >nul

echo [*] Stripping debug symbols...
if exist "C:\Users\angel\scoop\apps\gcc\current\bin\strip.exe" (
    "C:\Users\angel\scoop\apps\gcc\current\bin\strip.exe" "%DIST_DIR%\gcad.exe"
    echo [+] GCC strip completed.
) else (
    where strip >nul 2>&1
    if errorlevel 0 (
        strip "%DIST_DIR%\gcad.exe"
        echo [+] System strip completed.
    ) else (
        echo [!] Strip tool not found, preserving unstripped binary.
    )
)

echo [+] Portable distribution package created successfully:
echo     Path: %DIST_DIR%
echo.
dir "%DIST_DIR%"

@echo off
title DevSecOps Risk Intelligence Pipeline
echo.
echo ============================================================
echo   DevSecOps Risk Intelligence Pipeline — One-Command Launch
echo ============================================================
echo.

:: Find Git Bash
set "BASH="
where git >nul 2>&1 && (
    for /f "tokens=*" %%i in ('where git') do (
        set "GITDIR=%%~dpi"
        set "BASH=!GITDIR!bin\bash.exe"
        goto :found
    )
)

:found
:: Try common Git Bash locations
if exist "C:\Program Files\Git\bin\bash.exe" set "BASH=C:\Program Files\Git\bin\bash.exe"
if exist "C:\Program Files (x86)\Git\bin\bash.exe" set "BASH=C:\Program Files (x86)\Git\bin\bash.exe"

if "%BASH%"=="" (
    echo [X] Git Bash not found!
    echo     Install Git for Windows from https://git-scm.com/download/win
    echo     Then re-run this file.
    pause
    exit /b 1
)

echo [*] Found Git Bash: %BASH%
echo [*] Starting full pipeline setup...
echo.

:: Get the directory of this batch file
set "SCRIPT_DIR=%~dp0"

:: Run the bash script
"%BASH%" "%SCRIPT_DIR%setup_and_run.sh"

echo.
echo ============================================================
echo   Done! Dashboard should be opening in your browser.
echo   Or open http://localhost:8000 manually.
echo ============================================================
pause

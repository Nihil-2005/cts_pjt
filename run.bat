@echo off
echo.
echo ============================================================
echo   DevSecOps Risk Intelligence Pipeline — Quick Start
echo ============================================================
echo.

REM Check for Git Bash
where bash >nul 2>&1
if %errorlevel% equ 0 (
    echo Starting full pipeline setup...
    echo.
    bash setup_and_run.sh
) else (
    echo Git Bash not found. Starting server directly...
    echo.
    if exist venv\Scripts\activate (
        call venv\Scripts\activate
    )
    python -m pipeline.server
)

echo.
echo Dashboard: http://localhost:8000
if defined DASHBOARD_PASS (
    echo Login:     admin / %DASHBOARD_PASS%
) else (
    echo Login:     admin / (auto-generated — check terminal output)
)
echo.
pause

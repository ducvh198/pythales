@echo off
REM ==============================================================================
REM PyThales HSM Simulator - Docker Build & Push Batch Wrapper
REM ==============================================================================

setlocal

set "SCRIPT_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%build-and-push.ps1" %*

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build or push failed with exit code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

endlocal

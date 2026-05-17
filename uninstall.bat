@echo off
setlocal

echo === Peregrine Uninstall ===

net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Run as Administrator
    exit /b 1
)

fltmc unload Peregrine >nul 2>&1
sc.exe stop Peregrine >nul 2>&1
sc.exe delete Peregrine >nul 2>&1

set INF=C:\Peregrine\PeregrineKernelComponent.inf
if exist "%INF%" (
    rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 %INF%
)

echo Done.
pause

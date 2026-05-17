@echo off
setlocal

set SRC=%~dp0
set DEST=C:\Peregrine
set SYS=%DEST%\PeregrineKernelComponent.sys
set INF=%DEST%\PeregrineKernelComponent.inf

echo === Peregrine Install ===

:: Check admin
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Run as Administrator
    exit /b 1
)

:: Copy files
if not exist "%DEST%" mkdir "%DEST%"
copy /Y "%SRC%src\PeregrineKernelComponent\PeregrineKernelComponent\PeregrineKernelComponent.inf" "%INF%"
if exist "%SRC%src\PeregrineKernelComponent\x64\Release\PeregrineKernelComponent.sys" (
    copy /Y "%SRC%src\PeregrineKernelComponent\x64\Release\PeregrineKernelComponent.sys" "%SYS%"
)

:: Stop old service/filter if running
sc.exe stop Peregrine >nul 2>&1
fltmc unload Peregrine >nul 2>&1
sc.exe delete Peregrine >nul 2>&1
timeout /t 1 /nobreak >nul

:: Install via INF
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 %INF%

echo.
echo === Installed. Start with: ===
echo   sc.exe start Peregrine
echo   -or-
echo   fltmc load Peregrine
echo.
echo === Uninstall with: ===
echo   uninstall.bat
echo.

pause

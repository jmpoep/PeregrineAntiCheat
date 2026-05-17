@echo off
where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)
cl /nologo /O2 game.c /Fe:game.exe
cl /nologo /O2 cheat.c /Fe:cheat.exe
echo.
echo Built: game.exe + cheat.exe
echo.
echo Usage:
echo   1. Start game.exe
echo   2. Note the PID and address
echo   3. Start cheat.exe ^<PID^> ^<address^>
echo   4. Watch health change from 100 to 9999

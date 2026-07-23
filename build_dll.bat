@echo off
setlocal

set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
set DLL_SLN=src\PeregrineDLL\PeregrineDLL.sln
set DRV_SLN=src\PeregrineKernelComponent\PeregrineKernelComponent.sln
set DEST=src\Userland

echo === Building PeregrineGame Release x64 ===
%MSBUILD% %DLL_SLN% /p:Configuration=Release /p:Platform=x64 /p:PeregrineRole=Game /m /v:minimal
if %ERRORLEVEL% neq 0 (
    echo ERROR: Game DLL x64 build failed
    exit /b 1
)

echo === Building PeregrineSensor Release x64 ===
%MSBUILD% %DLL_SLN% /p:Configuration=Release /p:Platform=x64 /p:PeregrineRole=Sensor /m /v:minimal
if %ERRORLEVEL% neq 0 (
    echo ERROR: Sensor DLL x64 build failed
    exit /b 1
)

echo === Building PeregrineGame Release x86 ===
%MSBUILD% %DLL_SLN% /p:Configuration=Release /p:Platform=x86 /p:PeregrineRole=Game /m /v:minimal
if %ERRORLEVEL% neq 0 (
    echo ERROR: Game DLL x86 build failed
    exit /b 1
)

echo === Building PeregrineSensor Release x86 ===
%MSBUILD% %DLL_SLN% /p:Configuration=Release /p:Platform=x86 /p:PeregrineRole=Sensor /m /v:minimal
if %ERRORLEVEL% neq 0 (
    echo ERROR: Sensor DLL x86 build failed
    exit /b 1
)

echo === Building PeregrineKernelComponent Release x64 ===
%MSBUILD% %DRV_SLN% /p:Configuration=Release /p:Platform=x64 /m /v:minimal
if %ERRORLEVEL% neq 0 (
    echo ERROR: Driver build failed
    exit /b 1
)

echo === Copying files to %DEST% ===
if not exist "%DEST%" mkdir "%DEST%"
copy /Y "src\PeregrineDLL\x64\Release\Game\PeregrineGame.dll" "%DEST%\PeregrineGame_x64.dll"
copy /Y "src\PeregrineDLL\x64\Release\Sensor\PeregrineSensor.dll" "%DEST%\PeregrineSensor_x64.dll"
copy /Y "src\PeregrineDLL\Release\Game\PeregrineGame.dll" "%DEST%\PeregrineGame_x86.dll"
copy /Y "src\PeregrineDLL\Release\Sensor\PeregrineSensor.dll" "%DEST%\PeregrineSensor_x86.dll"
copy /Y "src\PeregrineKernelComponent\x64\Release\PeregrineKernelComponent.sys" "%DEST%\PeregrineKernelComponent.sys"

echo === Copying to C:\Peregrine ===
if not exist "C:\Peregrine" mkdir "C:\Peregrine"
copy /Y "src\PeregrineDLL\x64\Release\Game\PeregrineGame.dll" "C:\Peregrine\PeregrineGame_x64.dll"
copy /Y "src\PeregrineDLL\x64\Release\Sensor\PeregrineSensor.dll" "C:\Peregrine\PeregrineSensor_x64.dll"
copy /Y "src\PeregrineDLL\Release\Game\PeregrineGame.dll" "C:\Peregrine\PeregrineGame_x86.dll"
copy /Y "src\PeregrineDLL\Release\Sensor\PeregrineSensor.dll" "C:\Peregrine\PeregrineSensor_x86.dll"
copy /Y "src\PeregrineKernelComponent\x64\Release\PeregrineKernelComponent.sys" "C:\Peregrine\PeregrineKernelComponent.sys"
if exist "src\peregrine-tauri\src-tauri\target\release\peregrine-tauri.exe" (
    copy /Y "src\peregrine-tauri\src-tauri\target\release\peregrine-tauri.exe" "C:\Peregrine\peregrine-tauri.exe"
)

echo === Done ===
dir "C:\Peregrine\"

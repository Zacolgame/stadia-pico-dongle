@echo off
rem stadia-one firmware build + offline gates (ASCII-only).
rem Prerequisites (all on PATH or via env vars):
rem   cmake, ninja, arm-none-eabi-gcc, picotool, python, Visual Studio Build Tools (for picotool host build)
rem   PICO_SDK_PATH = path to pico-sdk 2.1.x
rem   PICO_TOOLCHAIN_PATH = path to arm-gnu-toolchain (optional if gcc is on PATH)
rem Usage:  build.bat
rem Output: build\stadia_one.uf2  (drag onto the RP2350 USB drive, or: python tools\raw-serial.py COMx flash build\stadia_one.uf2)
if "%PICO_SDK_PATH%"=="" (
  echo [FATAL] set PICO_SDK_PATH to your pico-sdk 2.1.x checkout.
  exit /b 9
)
where cmake >nul 2>&1 || (echo [FATAL] cmake not on PATH. & exit /b 9)
where ninja >nul 2>&1 || (echo [FATAL] ninja not on PATH. & exit /b 9)
where arm-none-eabi-gcc >nul 2>&1 || (
  if not "%PICO_TOOLCHAIN_PATH%"=="" set "PATH=%PICO_TOOLCHAIN_PATH%\bin;%PATH%"
)
where arm-none-eabi-gcc >nul 2>&1 || (echo [FATAL] arm-none-eabi-gcc not on PATH. & exit /b 9)
where python >nul 2>&1 || (echo [FATAL] python not on PATH. & exit /b 9)
rem ---- host C++ compiler (pioasm/picotool build with it); best effort ----
for %%E in (BuildTools Community Professional Enterprise) do (
  if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
  )
  if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
  )
)
cd /d %~dp0
cmake -S . -B build -G Ninja -DPICO_BOARD=pico2_w -DPICO_PLATFORM=rp2350
if errorlevel 1 exit /b 1
cmake --build build
if errorlevel 1 exit /b 1
rem ---- offline gates (no hardware needed) ----
python tests\check_usb_desc.py
if errorlevel 1 exit /b 1
python verify_uf2.py build\stadia_one.uf2 build\stadia_one.bin
if errorlevel 1 exit /b 1
python tests\oracle_rpc.py
if errorlevel 1 exit /b 1
python tests\check_rumble.py
if errorlevel 1 exit /b 1
python tests\check_ipv6_ra.py
if errorlevel 1 exit /b 1
echo BUILD + GATES OK: build\stadia_one.uf2

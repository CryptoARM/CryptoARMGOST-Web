@echo off

set CRYPTOPRO_HOME="C:\\Program Files\\Crypto Pro\\CSP"
set CRYPTOPRO=%CRYPTOPRO_HOME%\certmgr.exe
set RESOURCES_HOME=%~dp0

set PFX1=%RESOURCES_HOME%\sha1.pfx
set PFX256=%RESOURCES_HOME%\sha256.pfx
set PFX384=%RESOURCES_HOME%\sha384.pfx
set PFX512=%RESOURCES_HOME%\sha512.pfx

set ROOT1=%RESOURCES_HOME%\1.cer
set ROOT256=%RESOURCES_HOME%\256.cer
set ROOT384=%RESOURCES_HOME%\384.cer
set ROOT512=%RESOURCES_HOME%\512.cer


@echo "RSA SHA-1"
%CRYPTOPRO% -install -pfx -file %PFX1% -pin "12345678" -keep_exportable
%CRYPTOPRO% -install -cert -file %ROOT1% -store uRoot

@echo "RSA SHA 256"
%CRYPTOPRO% -install -pfx -file %PFX256% -pin "12345678" -keep_exportable
%CRYPTOPRO% -install -cert -file %ROOT256% -store uRoot

@echo "RSA SHA 384"
%CRYPTOPRO% -install -pfx -file %PFX384% -pin "12345678" -keep_exportable
%CRYPTOPRO% -install -cert -file %ROOT384% -store uRoot

@echo "RSA SHA 512"
%CRYPTOPRO% -install -pfx -file %PFX512% -pin "12345678" -keep_exportable
%CRYPTOPRO% -install -cert -file %ROOT512% -store uRoot

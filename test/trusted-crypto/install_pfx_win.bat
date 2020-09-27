@echo off

set CRYPTOPRO_HOME="C:\\Program Files\\Crypto Pro\\CSP"
set CRYPTOPRO=%CRYPTOPRO_HOME%\certmgr.exe
set RESOURCES_HOME=%~dp0resources

set PFX2001=%RESOURCES_HOME%\pfx2001.pfx
set PFX2012_256=%RESOURCES_HOME%\pfx2012-256.pfx
set PFX2012_512=%RESOURCES_HOME%\pfx2012-512.pfx

set ROOT2001=%RESOURCES_HOME%\root2001.cer
set ROOT2012=%RESOURCES_HOME%\root2012.cer

@echo "Gost 2001"
%CRYPTOPRO% -install -pfx -file %PFX2001% -pin "1" -keep_exportable
%CRYPTOPRO% -install -cert -file %ROOT2001% -store uRoot 

@echo "Gost 2012-256"
%CRYPTOPRO% -install -pfx -file %PFX2012_256% -pin "1" -keep_exportable
%CRYPTOPRO% -install -cert -file %ROOT2012% -store uRoot

@echo "Gost 2012-512"
%CRYPTOPRO% -install -pfx -file %PFX2012_512% -pin "1" -keep_exportable
%CRYPTOPRO% -install -cert -file %ROOT2012% -store uRoot
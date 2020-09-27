@echo off

set CRYPTOPRO_HOME="C:\\Program Files\\Crypto Pro\\CSP"
set CRYPTOPRO=%CRYPTOPRO_HOME%\certmgr.exe
set RESOURCES_HOME=%~dp0resources

%CRYPTOPRO% -install -pfx -file KU-digitalSignature-keyEncipherment.pfx -pin "1" -keep_exportable
%CRYPTOPRO% -install -pfx -file KU-keyEncipherment.pfx -pin "1" -keep_exportable
%CRYPTOPRO% -install -pfx -file KU-digitalSignature.pfx -pin "1" -keep_exportable
%CRYPTOPRO% -install -pfx -file KU-none.pfx -pin "1" -keep_exportable

%CRYPTOPRO% -install -cert -file KU-cacert.cer -store uRoot 

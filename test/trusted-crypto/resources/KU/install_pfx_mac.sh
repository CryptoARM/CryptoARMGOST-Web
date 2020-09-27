#!/bin/sh


CRYPTOPRO_HOME=/opt/cprocsp/bin/
CRYPTOPRO=$CRYPTOPRO_HOME/certmgr

$CRYPTOPRO -install -pfx -file KU-digitalSignature-keyEncipherment.pfx -pin "1" -keep_exportable
$CRYPTOPRO -install -pfx -file KU-keyEncipherment.pfx -pin "1" -keep_exportable
$CRYPTOPRO -install -pfx -file KU-digitalSignature.pfx -pin "1" -keep_exportable
$CRYPTOPRO -install -pfx -file KU-none.pfx -pin "1" -keep_exportable

$CRYPTOPRO -install -cert -file KU-cacert.cer -store uRoot

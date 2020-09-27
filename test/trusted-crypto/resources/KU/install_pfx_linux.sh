#!/bin/bash

# available values of ARCH: "ia32", "amd64"
# ARCH="ia32"
ARCH="amd64"

CRYPTOPRO_HOME=/opt/cprocsp/bin/$ARCH
CRYPTOPRO=$CRYPTOPRO_HOME/certmgr

$CRYPTOPRO -install -pfx -file KU-digitalSignature-keyEncipherment.pfx -pin "1" -keep_exportable
$CRYPTOPRO -install -pfx -file KU-keyEncipherment.pfx -pin "1" -keep_exportable
$CRYPTOPRO -install -pfx -file KU-digitalSignature.pfx -pin "1" -keep_exportable
$CRYPTOPRO -install -pfx -file KU-none.pfx -pin "1" -keep_exportable

$CRYPTOPRO -install -cert -file KU-cacert.cer -store uRoot

#!/bin/bash

# available values of ARCH: "ia32", "amd64"
# ARCH="ia32"
ARCH="amd64"

CRYPTOPRO_HOME=/opt/cprocsp/bin/$ARCH
CRYPTOPRO=$CRYPTOPRO_HOME/certmgr
RESOURCES_HOME=$(dirname $(realpath "$0"))/resources

PFX2001=$RESOURCES_HOME/pfx2001.pfx
PFX2012_256=$RESOURCES_HOME/pfx2012-256.pfx
PFX2012_512=$RESOURCES_HOME/pfx2012-512.pfx

ROOT2001=$RESOURCES_HOME/root2001.cer
ROOT2012=$RESOURCES_HOME/root2012.cer

echo -e "\nGost 2001"
$CRYPTOPRO -install -pfx -file $PFX2001 -pin "1" -keep_exportable
sudo $CRYPTOPRO -install -cert -file $ROOT2001 -store mRoot

echo -e "\nGost 2012-256"
$CRYPTOPRO -install -pfx -file $PFX2012_256 -pin "1" -keep_exportable
sudo $CRYPTOPRO -install -cert -file $ROOT2012 -store mRoot

echo -e "\nGost 2012-512"
$CRYPTOPRO -install -pfx -file $PFX2012_512 -pin "1" -keep_exportable
sudo $CRYPTOPRO -install -cert -file $ROOT2012 -store mRoot


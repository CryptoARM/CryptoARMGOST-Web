#!/bin/bash

# available values of ARCH: "ia32", "amd64"
# ARCH="ia32"
ARCH="amd64"

CRYPTOPRO_HOME=/opt/cprocsp/bin/$ARCH
CRYPTOPRO=$CRYPTOPRO_HOME/certmgr
RESOURCES_HOME=$(dirname $(realpath "$0"))

PFX1=$RESOURCES_HOME/sha1.pfx
PFX256=$RESOURCES_HOME/sha256.pfx
PFX384=$RESOURCES_HOME/sha384.pfx
PFX512=$RESOURCES_HOME/sha512.pfx

ROOT1=$RESOURCES_HOME/1.cer
ROOT256=$RESOURCES_HOME/256.cer
ROOT384=$RESOURCES_HOME/384.cer
ROOT512=$RESOURCES_HOME/512.cer

echo -e "\nSHA-1"
$CRYPTOPRO -install -pfx -file $PFX1 -pin "1" -keep_exportable
sudo $CRYPTOPRO -install -cert -file $ROOT1 -store mRoot

echo -e "\nSHA 256"
$CRYPTOPRO -install -pfx -file $PFX256 -pin "1" -keep_exportable
sudo $CRYPTOPRO -install -cert -file $ROOT256 -store mRoot

echo -e "\nSHA 384"
$CRYPTOPRO -install -pfx -file $PFX384 -pin "1" -keep_exportable
sudo $CRYPTOPRO -install -cert -file $ROOT384 -store mRoot

echo -e "\nSHA 512"
$CRYPTOPRO -install -pfx -file $PFX512 -pin "1" -keep_exportable
sudo $CRYPTOPRO -install -cert -file $ROOT512 -store mRoot

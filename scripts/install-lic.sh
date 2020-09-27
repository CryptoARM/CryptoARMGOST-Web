#!/bin/sh

lic_dir="/etc/opt/Trusted/CryptoARM Server"

if [ -f "${lic_dir}/license.lic" ]
then
  read -p "License file already exists. Overwrite? (y/n): " in
  if [ ! "${in}" = "y" ] && [ ! "${in}" = "Y" ]
  then
    printf "\nOverwrite is not confirmed. Exiting..."
    exit 1
  fi
fi

read -p "Enter license code: " in

if [ -z "${in}" ]
then
  printf "\nError: License code is not entered!\n"
  exit 1
fi

lic_code=${in}

if [ ! -d "${lic_dir}" ]
then
  mkdir -p "${lic_dir}"
  chmod 777 "${lic_dir}"
fi

if [ ! -d "${lic_dir}" ]
then
  printf "\nError: Unable to create license directory ${lic_dir}\n"
  exit 1
fi

printf "${lic_code}" > "${lic_dir}/license.lic"
if [ ! -f "${lic_dir}/license.lic" ]
then
  printf "\nError: Unable to create license file.\n"
  exit 1
fi

printf "\nLicense has been saved successfully.\n"

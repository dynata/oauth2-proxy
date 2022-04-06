#!/bin/bash

set -e

function decode {
  _l=$((${#1} % 4))
  if [ $_l -eq 2 ]; then _s="$1"'=='
  elif [ $_l -eq 3 ]; then _s="$1"'='
  else _s="$1" ; fi
  echo "$_s"
}

function hex {
  echo $1 | base64 -d | od -A n -t x1 | sed 's/ *//g' | tr -d '\n'
}

_mydir="`pwd`"

RSA_PRIVATE_FILE=${_mydir}/kc.local.private.pem
HMAC_KEY_FILE=${_mydir}/kc.hmac.secret.hex
if [[ -f "${RSA_PRIVATE_FILE}" && -f "${HMAC_KEY_FILE}" ]]; then
    echo "kc RSA/HMAC files already exist locally"
else
    echo "kc RSA/HMAC files do NOT exist locally. start preparing..."
    mysql --host=127.0.0.1 --port=13306 --user=root --password=root < kcComponentConfig.sql | awk -F ' ' '{print $2}' | sed -e '1d' > kc.temp
    kc_local_temp="./kc.temp"
    kc_hmac_secret=$(head -n 1 ${kc_local_temp})
    # echo "kc hmac secret value: ${kc_hmac_secret}"
    kc_rsa_private=$(sed "2q;d" ${kc_local_temp})
    # echo "kc rsa privateKey: ${kc_rsa_private}"
    rm $kc_local_temp

    # convert hmac secret key to hexed and export as env var in current shell
    kc_hmac_secret_with_padding=$(decode ${kc_hmac_secret})
    echo "hmac with padding: " ${kc_hmac_secret_with_padding}
    kc_hmac_secret_hexed=$(hex ${kc_hmac_secret_with_padding})
    echo ${kc_hmac_secret_hexed} > ${HMAC_KEY_FILE}

    # convert kc rsa private key to lkey file in local home dir
    echo ${kc_rsa_private} | base64 -d | openssl rsa -inform DER -out $RSA_PRIVATE_FILE
  
fi

# if local keycloak RSA/HMAC keys files already exist. export env vars used by barbican server
export KC_HMAC_SECRET_HEX=`cat ${HMAC_KEY_FILE}`
echo "KC_HMAC_SECRET_HEX => ${HMAC_KEY_FILE}"

export KC_RSA_PRIVATE_PATH=${RSA_PRIVATE_FILE}
echo "KC_RSA_PRIVATE_PATH => ${KC_RSA_PRIVATE_PATH}"

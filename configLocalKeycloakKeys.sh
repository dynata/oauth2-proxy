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
    DB_HOST="${DATABASE_HOST:-127.0.0.1}"
    DB_PORT="${DATABASE_PORT:-13306}"
    DB_USER="${DATABASE_USERNAME:-root}"
    DB_PASS="${DATABASE_PASSWORD:-root}"
    mysql --host=${DB_HOST} --port=${DB_PORT} --user=${DB_USER} --password=${DB_PASS} < kcComponentConfig.sql | awk -F ' ' '{print $2}' | sed -e '1d' > kc.temp
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
    kc_rsa_private_Key=`echo ${kc_rsa_private} | base64 -d | openssl rsa -inform DER`
    echo "${kc_rsa_private_Key}" > $RSA_PRIVATE_FILE
    
    ENV="${ENVIRONMENT:-local-environment}"
    dotEnvDestFile="contrib/$ENV/.env"
    echo "" > $dotEnvDestFile
    if [ -f "$dotEnvDestFile" ]
    then
        # saving to .env file for use in docker-compose.yml
        echo "wirting to $dotEnvDestFile file"
        echo "ENVIRONMENT='${ENV}'" > "$dotEnvDestFile"
        echo "KC_HMAC_SECRET_KEY_HEX='$kc_hmac_secret_hexed'" >> "$dotEnvDestFile"
        echo "KC_PRIVATE_KEY='$kc_rsa_private_Key'" >> "$dotEnvDestFile"
    fi
  
fi

# if local keycloak RSA/HMAC keys files already exist. export env vars used by barbican server
export KC_HMAC_SECRET_HEX=`cat ${HMAC_KEY_FILE}`
echo "KC_HMAC_SECRET_HEX => ${HMAC_KEY_FILE}"

export KC_RSA_PRIVATE_PATH=${RSA_PRIVATE_FILE}
echo "KC_RSA_PRIVATE_PATH => ${KC_RSA_PRIVATE_PATH}"

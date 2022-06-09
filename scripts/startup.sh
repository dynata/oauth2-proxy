#!/bin/bash
if [ -z "$ENVIRONMENT" ] 
then echo "ENVIRONMENT is unset" 
else echo "ENVIRONMENT is set to '$ENVIRONMENT'" 
fi
if [ -z "$KC_HMAC_SECRET_KEY_HEX" ] 
then echo "KC_HMAC_SECRET_KEY_HEX is unset" 
else echo "KC_HMAC_SECRET_KEY_HEX is set" 
fi
if [ -z "$KC_PRIVATE_KEY" ] 
then echo "KC_PRIVATE_KEY is unset" 
else echo "KC_PRIVATE_KEY is set" 
fi

ENV="${ENVIRONMENT:-local-environment}"


if [ "$ENV" == "local-environment" ] 
then
  echo "executing local-environment environment configuration"
  # /bin/oauth2-proxy --config=/oauth2-proxy.cfg # mounted from docker-compose with correct configuration file
  /bin/dlv --listen=:41800 --headless=true --api-version=2 --accept-multiclient exec /bin/oauth2-proxy --continue -- --config=/oauth2-proxy.cfg
else
  echo "executing non-local environment ($ENV) configuration"
  cd /dynata/oauth2-proxy/contrib/$ENV/
  echo $ANSIBLE_SECRET > ansible-password.txt
  ansible-vault decrypt --vault-password-file ansible-password.txt oauth2-proxy-keycloak.cfg
  /bin/oauth2-proxy --config=/dynata/oauth2-proxy/contrib/$ENV/oauth2-proxy-keycloak.cfg --silence-ping-logging
fi
#!/bin/ash
cd /dynata/oauth2-proxy/contrib/$ENVIRONMENT/
echo $ANSIBLE_SECRET > ansible-password.txt
ansible-vault decrypt --vault-password-file ansible-password.txt oauth2-proxy-keycloak.cfg

/bin/oauth2-proxy --config=/dynata/oauth2-proxy/contrib/$ENVIRONMENT/oauth2-proxy-keycloak.cfg
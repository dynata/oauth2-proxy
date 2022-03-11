.PHONY: up
up:
	docker-compose up -d

.PHONY: %
%:
	docker-compose $*

.PHONY: alpha-config-up
alpha-config-up:
	docker-compose -f docker-compose.yaml -f docker-compose-alpha-config.yaml up -d

.PHONY: alpha-config-%
alpha-config-%:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml $*

.PHONY: nginx-up
nginx-up:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml up -d

.PHONY: nginx-%
nginx-%:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml $*

.PHONY: keycloak-up
keycloak-up:
	docker-compose -f docker-compose-keycloak.yaml up -d

.PHONY: keycloak-%
keycloak-%:
	docker-compose -f docker-compose-keycloak.yaml $*

.PHONY: keycloak-nginx-up
keycloak-nginx-up:
	docker-compose -f docker-compose-nginx-keycloak.yaml up -d

.PHONY: keycloak-nginx-%
keycloak-nginx-%:
	docker-compose -f docker-compose-nginx-keycloak.yaml $*

.PHONY: pe-dev-nginx-up
pe-dev-nginx-up:
	docker-compose -f docker-compose-nginx-pe-env.yaml up -d

.PHONY: pe-dev-nginx-%
pe-dev-nginx-%:
	docker-compose -f docker-compose-nginx-pe-env.yaml $*

.PHONY: pe-dev-nginx-folio3-up
pe-dev-nginx-folio3-up:
	docker-compose -f docker-compose-nginx-pe-env-folio3.yaml up -d

.PHONY: pe-dev-nginx-folio3-%
pe-dev-nginx-folio3-%:
	docker-compose -f docker-compose-nginx-pe-env-folio3.yaml $*

.PHONY: kubernetes-up
kubernetes-up:
	make -C kubernetes create-cluster
	make -C kubernetes deploy

.PHONY: kubernetes-down
kubernetes-down:
	make -C kubernetes delete-cluster

.PHONY: traefik-up
traefik-up:
	docker-compose -f docker-compose.yaml -f docker-compose-traefik.yaml up -d

.PHONY: traefik-%
traefik-%:
	docker-compose -f docker-compose.yaml -f docker-compose-traefik.yaml $*

# Night Shift. `make help` lists the targets.
SHELL := /bin/bash
PY ?= .venv/bin/python
K3D_CLUSTER ?= beacon
export K3D_CLUSTER

.PHONY: help setup test-services test lint web cluster up down snapshot break-netpol bad-deploy restore e2e logs demo-up demo-status demo-trigger demo-reset demo-verify demo-down hackathon-verify

help:
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

setup: ## create .venv and install backend + frontend dependencies
	uv venv .venv && uv pip install --python $(PY) -e '.[dev]' && cd web && npm ci

test-services: ## throwaway PostgreSQL (5433) and OPA (8281) for the unit tests
	-docker run -d --name beacon-test-pg -e POSTGRES_USER=beacon -e POSTGRES_PASSWORD=beacon -e POSTGRES_DB=beacon -p 5433:5432 postgres:16-alpine
	-docker run -d --name beacon-test-opa -p 8281:8181 -v $(PWD)/policy:/policy:ro openpolicyagent/opa:1.0.0 run --server --addr=0.0.0.0:8181 /policy

test: ## backend unit tests (needs test-services)
	$(PY) -m pytest tests -q

lint: ## ruff + frontend type check
	$(PY) -m ruff check src tests scripts && cd web && npm run typecheck

web: ## type check and build the console
	cd web && npm run build

cluster: ## create the k3d cluster with API-server audit logging
	deploy/k3s/make-audit-webhook.sh
	k3d cluster create --config deploy/k3s/k3d-config.yaml

up: ## build images and deploy the whole stack to the current cluster
	deploy/up.sh

down: ## delete the k3d cluster
	k3d cluster delete $(K3D_CLUSTER)

snapshot: ## record the golden NetworkPolicy snapshot (run on a healthy cluster)
	kubectl -n beacon exec deploy/beacon-worker -- python -m beacon.snapshot

break-netpol: ## Demo 1: remove the NetworkPolicy ingress rule
	demo/trigger.sh break-netpol

bad-deploy: ## Demo 2: roll out a version that crashes on start
	demo/trigger.sh bad-deploy

restore: ## put the demo back by hand
	demo/trigger.sh restore

e2e: ## both demos and the RBAC checks against the live cluster
	BEACON_E2E=1 $(PY) -m pytest tests/test_integration.py -m integration -q

demo-up: ## start NATS/OPA/API/Pathway/worker/simulator/console (DEMO_MODE=sim|live)
	scripts/demo.sh up

demo-status: ## integration health from the running API
	scripts/demo.sh status

demo-trigger: ## trigger the NetworkPolicy incident (sim: DEMO_SIMULATOR; live: demo/trigger.sh)
	scripts/demo.sh trigger

demo-reset: ## clear demo data, reset the simulator, restart Pathway
	scripts/demo.sh reset

demo-verify: ## run the browser journey against the running stack
	NODE_PATH=$$(npm root -g) node e2e/journey.mjs

demo-down: ## stop everything demo-up started
	scripts/demo.sh down

hackathon-verify: ## tests + build + (if running) journey -> .agent/verification-results.json
	$(PY) scripts/hackathon_verify.py

logs: ## follow the worker
	kubectl -n beacon logs -f deploy/beacon-worker

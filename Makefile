# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Makefile for trino.oAuth2 library

BASES = run

default: $(BASES)

# use bash so that `source` works
SHELL := /bin/bash

# Filter out known targets from the command line goals to get extra flags
EXTRA_ARGS := $(filter-out logs,$(MAKECMDGOALS))

setup:
	if [ ! -d "venv" ]; then \
		python3 -m venv venv && \
		. venv/bin/activate && \
		pip install -r requirements-dev.txt; \
	fi

pull:
	docker pull oryd/hydra:v25.4.0
	docker pull oryd/hydra-login-consent-node:v25.4.0

build-test:
	docker compose -f tests/docker-compose.yml build test

start-hydra:
	docker-compose -f tests/docker-compose.yml up -d

stop-hydra:
	docker-compose -f tests/docker-compose.yml down

restart-hydra:
	$(MAKE) stop-hydra
	$(MAKE) start-hydra
	@echo "Waiting for Hydra to be ready..."
	@sleep 5
	$(MAKE) configure-hydra

configure-hydra:
	. venv/bin/activate && \
	unset HTTP_PROXY && \
	unset http_proxy && \
	python tests/configure_hydra.py

test:
	. venv/bin/activate && \
	export KEYRING_CRYPTFILE_PASSWORD=password123 && \
	pytest -s tests/

container-test: build-test
	docker compose -f tests/docker-compose.yml run --rm test

shell: build-test
	docker compose -f tests/docker-compose.yml run --rm --entrypoint bash test

test-device-curl:
	curl --noproxy '*' -s -S -X POST -d "client_id=device-code-client&client_secret=device-code-secret&scope=offline" http://localhost:4444/oauth2/device/auth

# Phony target to treat flags as targets
-f:
	@:

logs:
	docker logs $(EXTRA_ARGS) hydra

pycharm:
	. venv/bin/activate && \
	unset HTTP_PROXY && \
	unset http_proxy && \
	/opt/pycharm/bin/pycharm.sh .

lint:
	. venv/bin/activate && \
	python -m pylint --output-format=colorized --msg-template '{path} line {line}: [{symbol}] {msg}' src/trino/oauth2 tests

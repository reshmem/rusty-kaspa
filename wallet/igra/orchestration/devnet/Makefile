SHELL := /bin/sh

.PHONY: build up up-miner down logs bootstrap fund devnet-all

build:
	docker compose build

bootstrap:
	./scripts/bootstrap_wallet.sh

up:
	docker compose up --build -d kaspad kaspaminer igra-signer-1 igra-signer-2 igra-signer-3

up-miner:
	docker compose up -d kaspaminer

down:
	docker compose down

logs:
	docker compose logs -f kaspad

fund:
	./scripts/fund_multisig.sh multisig-addresses.txt

devnet-all:
	$(MAKE) build
	$(MAKE) bootstrap
	$(MAKE) up

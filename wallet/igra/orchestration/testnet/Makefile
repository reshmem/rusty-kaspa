SHELL := /bin/sh

.PHONY: hyperlane-build hyperlane-up hyperlane-down hyperlane-logs

hyperlane-build:
	cd hyperlane && docker compose build

hyperlane-up:
	cd hyperlane && docker compose up -d

hyperlane-down:
	cd hyperlane && docker compose down

hyperlane-logs:
	cd hyperlane && docker compose logs -f

.PHONY: help build test scrape sync-research agent server docker-build docker-up clean

help:
	@echo "Targets:"
	@echo "  build          Build all four binaries to ./bin"
	@echo "  test           Run the full test suite"
	@echo "  scrape         Scrape VulnCheck docs into data/docs.db"
	@echo "  sync-research  Index local research/ notebooks into data/docs.db"
	@echo "  agent Q='...'  Run a single-shot CLI query"
	@echo "  server         Start the HTTP server on :8080"
	@echo "  docker-build   Build the Docker image"
	@echo "  docker-up      docker compose up server"
	@echo "  clean          Remove ./bin and ./data/docs.db"

build:
	mkdir -p bin
	go build -o bin/ ./cmd/...

test:
	go test ./...

scrape:
	go run ./cmd/scraper

sync-research:
	go run ./cmd/research-sync

agent:
	@test -n "$(Q)" || (echo "usage: make agent Q='your question'"; exit 1)
	go run ./cmd/agent "$(Q)"

server:
	go run ./cmd/server

docker-build:
	docker build -t checkdocs .

docker-up:
	docker compose up server

clean:
	rm -rf bin data/docs.db

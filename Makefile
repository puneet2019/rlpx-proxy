.PHONY: build docker-build docker-up docker-down monitor export

build:
	go build -o ./build/rlpx-proxy ./cmd/rlpx-proxy
	go build -o ./build/rlpx-monitor ./cmd/rlpx-monitor

monitor:
	docker compose logs -f rlpx-proxy | ./build/rlpx-monitor -db peers.json

export:
	./build/rlpx-monitor -db peers.json -export good-peers.json -min-score 5.0

docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

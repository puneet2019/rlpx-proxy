COMPOSE := docker compose -f example/docker-compose.yml

.PHONY: build clean up down logs peers stats export rebuild

# ── Build ────────────────────────────────────────────────────────────
build:
	go build -o ./build/rlpx-proxy ./cmd/rlpx-proxy
	go build -o ./build/rlpx-monitor ./cmd/rlpx-monitor

clean:
	rm -rf build/

rebuild: build
	$(COMPOSE) up -d --build rlpx-proxy

# ── Docker Compose ───────────────────────────────────────────────────
up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=50

logs-proxy:
	$(COMPOSE) logs -f --tail=50 rlpx-proxy

# ── API ──────────────────────────────────────────────────────────────
# Network stats (total peers, connected, best block, DHT pool)
stats:
	@curl -s localhost:8080/stats | python3 -m json.tool

# All peers with scores, chain head, latency, client
peers:
	@curl -s localhost:8080/peers | python3 -m json.tool

# Export enode list of peers above min score
export:
	@curl -s 'localhost:8080/peers/export?min_score=20' | python3 -m json.tool

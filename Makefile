IMAGE     ?= rlpx-proxy
TAG       ?= latest
PLATFORMS ?= linux/amd64,linux/arm64
COMPOSE   := docker compose -f example/docker-compose.yml

.PHONY: build clean test \
        docker-build docker-push docker-buildx \
        up down logs logs-proxy rebuild \
        stats peers export

# ── Local build ──────────────────────────────────────────────────────
build:
	@mkdir -p build
	go build -trimpath -o ./build/rlpx-proxy ./cmd/rlpx-proxy

clean:
	rm -rf build/

test:
	go vet ./...
	go test -v -count=1 -short ./...

# ── Docker ───────────────────────────────────────────────────────────
docker-build:
	docker build -t $(IMAGE):$(TAG) .

docker-push: docker-build
	docker push $(IMAGE):$(TAG)

docker-buildx:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE):$(TAG) --push .

# ── Docker Compose (example/) ───────────────────────────────────────
up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=50

logs-proxy:
	$(COMPOSE) logs -f --tail=50 rlpx-proxy

rebuild: build
	$(COMPOSE) up -d --build rlpx-proxy

# ── API helpers ──────────────────────────────────────────────────────
stats:
	@curl -s localhost:8080/stats | python3 -m json.tool

peers:
	@curl -s localhost:8080/peers | python3 -m json.tool

export:
	@curl -s 'localhost:8080/peers/export?min_score=20' | python3 -m json.tool

.PHONY: build clean

build:
	go build -o ./build/rlpx-proxy ./cmd/rlpx-proxy
	go build -o ./build/rlpx-monitor ./cmd/rlpx-monitor

clean:
	rm -rf build/

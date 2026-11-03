.PHONY: all build test clean run-daemon run-cli

all: build test

build:
	mkdir -p bin
	go build -o bin/netweaverd ./cmd/netweaverd
	go build -o bin/netweaver ./cmd/netweaver

test:
	go test -v ./...

clean:
	rm -rf bin/

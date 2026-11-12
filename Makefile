.PHONY: all build test clean bpf

all: build test

build:
	mkdir -p bin
	go build -o bin/netweaverd ./cmd/netweaverd
	go build -o bin/netweaver ./cmd/netweaver

# Regenerate the embedded eBPF object after editing bpf/netweaver.c.
# The compiled object is committed so builds do not require clang.
BPF_SRC := internal/classifier/bpf/netweaver.c
BPF_OBJ := internal/classifier/netweaver_bpfel.o
bpf:
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c $(BPF_SRC) -o $(BPF_OBJ)

test:
	go test -v ./...

clean:
	rm -rf bin/

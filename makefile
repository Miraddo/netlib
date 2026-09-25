# netlib
#
# "make" builds the user space tools in build/, "make test" checks them and
# "make run" builds the xdp detector and attaches it, which needs root.

CC ?= gcc
CLANG ?= clang
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra
BPF_CFLAGS ?= -O2 -Wall -target bpf
BUILD ?= build

TOOLS := $(BUILD)/netchecksum $(BUILD)/netdump $(BUILD)/netifinfo
NETUTIL := tools/netutil.c tools/netutil.h

.PHONY: all tools test detector run clean

all: tools

tools: $(TOOLS)

$(BUILD)/netchecksum: tools/checksum.c $(NETUTIL) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ tools/checksum.c tools/netutil.c

$(BUILD)/netdump: tools/pktdump.c $(NETUTIL) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ tools/pktdump.c tools/netutil.c

$(BUILD)/netifinfo: tools/ifinfo.c $(NETUTIL) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ tools/ifinfo.c tools/netutil.c

$(BUILD):
	mkdir -p $(BUILD)

test: tools
	tools/tests.sh $(BUILD)

# The detector needs clang for the bpf target and libbpf for the loader.
detector: detector.bpf.o loader

detector.bpf.o: detector/detector.c
	$(CLANG) $(BPF_CFLAGS) -c detector/detector.c -o detector.bpf.o

loader: detector/loader.c
	$(CC) detector/loader.c -o loader -lbpf

run: detector
	sudo ./loader

clean:
	rm -rf $(BUILD) detector.bpf.o loader

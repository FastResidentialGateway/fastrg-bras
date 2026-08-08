CC      := gcc
TARGET  := dpdk-bras

SRCS := src/main.c \
        src/pppoe.c \
        src/ppp.c \
        src/dhcpv6.c \
        src/ipv6.c \
        src/nat.c \
        src/arp.c \
        src/datapath.c

OBJS := $(SRCS:.c=.o)

DPDK_CFLAGS  := $(shell pkg-config --cflags libdpdk)
DPDK_LDFLAGS := $(shell pkg-config --libs libdpdk)

CFLAGS := -std=gnu11 -Wall -Wextra \
          -DALLOW_EXPERIMENTAL_API \
          -march=native \
          -Iinclude \
          $(DPDK_CFLAGS)

LDFLAGS := -Wl,--whole-archive \
           $(DPDK_LDFLAGS) \
           -Wl,--no-whole-archive

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

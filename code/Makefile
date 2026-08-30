CC ?= gcc
CFLAGS ?= -std=c17 -Wall -Wextra -Wpedantic -O2 -g
CPPFLAGS += -Iinclude -D_GNU_SOURCE
SANITIZE_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS := $(shell pkg-config --libs libsodium 2>/dev/null)
ifeq ($(strip $(SODIUM_LIBS)),)
  SODIUM_LIBS := -lsodium
endif

CFLAGS += $(SODIUM_CFLAGS)

CORE_SRCS := src/tun.c src/udp.c src/protocol.c src/crypto.c src/handshake.c src/replay.c src/util.c
CORE_OBJS := $(patsubst src/%.c,build/%.o,$(CORE_SRCS))

TEST_SRCS := tests/test_main.c tests/test_protocol.c tests/test_crypto.c tests/test_handshake.c tests/test_replay.c
TEST_LIB_SRCS := src/protocol.c src/crypto.c src/handshake.c src/replay.c src/util.c src/udp.c

.PHONY: all clean test test-sanitize debug dirs

all: dirs bin/svpn bin/svpn-keygen bin/tests

dirs:
	@mkdir -p bin build

build/%.o: src/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

bin/svpn: build/main.o $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(SODIUM_LIBS)

build/main.o: src/main.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

bin/svpn-keygen: tools/keygen.c src/crypto.c src/util.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tools/keygen.c src/crypto.c src/util.c $(SODIUM_LIBS)

bin/tests: $(TEST_SRCS) $(TEST_LIB_SRCS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(TEST_SRCS) $(TEST_LIB_SRCS) $(SODIUM_LIBS)

debug: CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -O0 -g $(SODIUM_CFLAGS)
debug: clean all

test: bin/tests
	./bin/tests

test-sanitize:
	@mkdir -p bin build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZE_FLAGS) -o bin/tests-sanitize \
		$(TEST_SRCS) $(TEST_LIB_SRCS) $(SODIUM_LIBS)
	./bin/tests-sanitize

clean:
	rm -rf bin build

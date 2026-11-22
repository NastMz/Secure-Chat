# SecureChat build. Requires a C11 compiler, pkg-config and libsodium.
#
#   make               build server and client into build/
#   make test          unit tests
#   make integration   end-to-end test (server + 2 clients + wire capture)
#   make check         unit + integration
#   make sanitize      everything again under AddressSanitizer + UBSan
#   make clean

CC       ?= cc
BUILD    ?= build
SANITIZE ?= 0
PYTHON   ?= python3

SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium)
SODIUM_LIBS   := $(shell pkg-config --libs libsodium)

WARNINGS := -Wall -Wextra -Werror -Wpedantic -Wshadow -Wformat=2 \
            -Wstrict-prototypes -Wmissing-prototypes -Wvla
CPPFLAGS += -D_DEFAULT_SOURCE -Iinclude -Isrc/client -Isrc/server $(SODIUM_CFLAGS)
CFLAGS   += -std=c11 $(WARNINGS) -MMD -MP

ifeq ($(SANITIZE),1)
CFLAGS  += -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
           -fno-sanitize-recover=all
LDFLAGS += -fsanitize=address,undefined
else
CFLAGS  += -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
endif
LDLIBS += $(SODIUM_LIBS)

COMMON_SRC := $(wildcard src/common/*.c)
SERVER_SRC := $(wildcard src/server/*.c)
CLIENT_SRC := $(wildcard src/client/*.c)
CLIENT_LIB := $(filter-out src/client/main.c,$(CLIENT_SRC))
SERVER_LIB := $(filter-out src/server/main.c,$(SERVER_SRC))
TEST_SRC   := $(wildcard tests/test_*.c)

obj = $(patsubst %.c,$(BUILD)/obj/%.o,$(1))

SERVER_BIN := $(BUILD)/securechat-server
CLIENT_BIN := $(BUILD)/securechat-client
TEST_BINS  := $(patsubst tests/%.c,$(BUILD)/tests/%,$(TEST_SRC))

.PHONY: all test integration check sanitize clean
.SECONDARY:

all: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(call obj,$(COMMON_SRC) $(SERVER_SRC))
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(CLIENT_BIN): $(call obj,$(COMMON_SRC) $(CLIENT_SRC))
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Unit tests link the common library and the client and server modules
# (everything except the two main() files).
$(BUILD)/tests/%: $(call obj,tests/%.c $(COMMON_SRC) $(CLIENT_LIB) $(SERVER_LIB))
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

test: $(TEST_BINS)
	@set -e; for t in $(TEST_BINS); do $$t; done

integration: all
	$(PYTHON) tests/integration_test.py $(BUILD)

check: test integration

sanitize:
	$(MAKE) BUILD=build-sanitize SANITIZE=1 check

clean:
	rm -rf build build-sanitize

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)

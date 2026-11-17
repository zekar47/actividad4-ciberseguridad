# a4-api -- build suckless: un binario, sin dependencias externas.
CC      ?= cc
CPPFLAGS = -D_FORTIFY_SOURCE=2 -I.
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
          -fstack-protector-strong -fPIE
LDFLAGS = -pie -Wl,-z,relro,-z,now
LDLIBS  =

PREFIX  ?= /usr/local
BIN      = api
SRC      = api.c
CONFIG   = config.h

.PHONY: all clean test install uninstall

all: $(BIN)

$(CONFIG): config.def.h
	cp config.def.h $@

$(BIN): $(SRC) $(CONFIG)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) $(LDFLAGS) $(LDLIBS) -o $@

test: $(BIN)
	python3 tests/test_api.py

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/a4-api

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/a4-api

clean:
	rm -f $(BIN) $(CONFIG)

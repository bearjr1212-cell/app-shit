# POS Framework - Native C Libraries Makefile
CC      := gcc
CFLAGS  := -shared -fPIC -O2 -Wall -Wextra -std=c11 -fvisibility=hidden
LDFLAGS :=

# No external dependencies - channel_hop uses raw netlink (no libnl)
# If libnl were needed: LDFLAGS += -lnl-3 -lnl-genl-3

INSTALL_DIR := /home/hilary/app-shit/posframework/lib

LIBS := libpacket_engine.so libchannel_hop.so libcrypto_parse.so libdeauth_craft.so libbeacon_flood.so

.PHONY: all clean install

all: $(LIBS)

libpacket_engine.so: packet_engine.c packet_engine.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libchannel_hop.so: channel_hop.c channel_hop.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libcrypto_parse.so: crypto_parse.c crypto_parse.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libdeauth_craft.so: deauth_craft.c deauth_craft.h packet_engine.c packet_engine.h
	$(CC) $(CFLAGS) -o $@ deauth_craft.c packet_engine.c $(LDFLAGS)

libbeacon_flood.so: beacon_flood.c beacon_flood.h packet_engine.c packet_engine.h
	$(CC) $(CFLAGS) -o $@ beacon_flood.c packet_engine.c $(LDFLAGS)

install: all
	@mkdir -p $(INSTALL_DIR)
	cp $(LIBS) $(INSTALL_DIR)/

clean:
	rm -f $(LIBS)

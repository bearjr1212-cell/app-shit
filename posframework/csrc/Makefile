# POS Framework - Native C Libraries Makefile
CC      := gcc
CFLAGS  := -shared -fPIC -O2 -Wall -Wextra -std=c11 -fvisibility=hidden
LDFLAGS :=

# No external dependencies - channel_hop uses raw netlink (no libnl)
# If libnl were needed: LDFLAGS += -lnl-3 -lnl-genl-3

INSTALL_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))/../lib

LIBS := libpacket_engine.so libchannel_hop.so libcrypto_parse.so libdeauth_craft.so libbeacon_flood.so libarp_spoof.so libsnmp_encode.so libpcap_write.so libtarget_pqueue.so libstate_machine.so libcrypto_accel.so libtkip_mic.so libccmp_aes.so

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

libarp_spoof.so: arp_spoof.c arp_spoof.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libsnmp_encode.so: snmp_encode.c snmp_encode.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libpcap_write.so: pcap_write.c pcap_write.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libtarget_pqueue.so: target_pqueue.c target_pqueue.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libstate_machine.so: state_machine.c state_machine.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libcrypto_accel.so: crypto_accel.c crypto_accel.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libtkip_mic.so: tkip_mic.c tkip_mic.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libccmp_aes.so: ccmp_aes.c ccmp_aes.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: all
	@mkdir -p $(INSTALL_DIR)
	cp $(LIBS) $(INSTALL_DIR)/

clean:
	rm -f $(LIBS)

# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	= pkt-gen

CLEANFILES = $(PROGS) *.o
NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I ../sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra

WITH_PCAP = 1
.ifdef WITH_PCAP
LDFLAGS += -lpcap
.else
CFLAGS += -DNO_PCAP
.endif

LDFLAGS += -lpthread
LDFLAGS += -lrt	# needed on linux, does not harm on BSD
#SRCS = pkt-gen.c

pkt-gen: pkt-gen.o sender.o receiver.o udp_packet.o start_threads.o ping.o pong.o icmp_packet.o pcap_reader.o extract.o
	$(CC) $(CFLAGS) -o pkt-gen pkt-gen.o sender.o receiver.o udp_packet.o start_threads.o ping.o pong.o icmp_packet.o pcap_reader.o extract.o $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)

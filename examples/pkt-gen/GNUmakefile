INCS = everything.h icmp_packet.h main_thread.h ping.h pkt-gen.c pong.h receiver.h sender.h start_threads.h udp_packet.h
SRCS = icmp_packet.c main_thread.c ping.c pong.c receiver.c sender.c start_threads.c udp_packet.c
PROGS = pkt-gen

SRCDIR ?= ../..
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra
WITH_PCAP = 1
ifdef WITH_PCAP
# do not use pcap by default, as it is not always available on linux
LDLIBS += -lpcap
else
CFLAGS += -DNO_PCAP
endif

LDLIBS += -lpthread
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

pkt-gen: pkt-gen.o sender.o main_thread.o receiver.o udp_packet.o start_threads.o ping.o pong.o icmp_packet.o
%-pic.o: %.c
	$(CC) $(CFLAGS) -fpic -c $^ -o $@

clean:
	@rm *.o $(PROGS)

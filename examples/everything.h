#pragma once

#define _GNU_SOURCE	/* for CPU_SET() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>	//getopt_long
#define NETMAP_WITH_LIBS
#include "net/netmap_user.h"

#include <ctype.h>	// isprint()
#include <unistd.h>	// sysconf()
#include <sys/poll.h>
#include <arpa/inet.h>	/* ntohs */
#include <sys/sysctl.h>	/* sysctl */
#include <ifaddrs.h>	/* getifaddrs */
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <pthread.h>

#ifndef NO_PCAP
#include <pcap/pcap.h>
#endif

#ifdef linux

#define cpuset_t        cpu_set_t

#define ifr_flagshigh  ifr_flags        /* only the low 16 bits here */
#define IFF_PPROMISC   IFF_PROMISC      /* IFF_PPROMISC does not exist */
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define CLOCK_REALTIME_PRECISE CLOCK_REALTIME
#include <netinet/ether.h>      /* ether_aton */
#include <linux/if_packet.h>    /* sockaddr_ll */
#endif  /* linux */

#ifdef __FreeBSD__
#include <sys/endian.h> /* le64toh */
#include <machine/param.h>

#include <pthread_np.h> /* pthread w/ affinity */
#include <sys/cpuset.h> /* cpu_set */
#include <net/if_dl.h>  /* LLADDR */
#endif  /* __FreeBSD__ */

#ifdef __APPLE__

#define cpuset_t        uint64_t        // XXX

#define pthread_setaffinity_np(a, b, c) ((void)a, 0)

#define ifr_flagshigh  ifr_flags        // XXX
#define IFF_PPROMISC   IFF_PROMISC
#include <net/if_dl.h>  /* LLADDR */
#define clock_gettime(a,b)      \
		do {struct timespec t0 = {0,0}; *(b) = t0; } while (0)
#endif  /* __APPLE__ */

#define SKIP_PAYLOAD 1 /* do not check payload. XXX unused */


#define VIRT_HDR_1	10	/* length of a base vnet-hdr */
#define VIRT_HDR_2	12	/* length of the extenede vnet-hdr */
#define VIRT_HDR_MAX	VIRT_HDR_2
struct virt_header {
	uint8_t fields[VIRT_HDR_MAX];
};

#define MAX_BODYSIZE	16384

struct pkt_udp {
	struct virt_header vh;
	struct ether_header eh;
	struct ip ip;
	struct udphdr udp;
	uint8_t body[MAX_BODYSIZE];	// XXX hardwired
} __attribute__((__packed__));

struct pkt_icmp {
	struct virt_header vh;
	struct ether_header eh;
	struct ip ip;
	struct icmphdr icmp;
	uint8_t body[MAX_BODYSIZE];	// XXX hardwired
} __attribute__((__packed__));

struct ip_range {
	char *name;
	uint32_t start, end; /* same as struct in_addr */
	uint16_t port0, port1;
};

struct mac_range {
	char *name;
	struct ether_addr start, end;
};

/* ifname can be netmap:foo-xxxx */
#define MAX_IFNAMELEN	64	/* our buffer for ifname */
//#define MAX_PKTSIZE	1536
#define MAX_PKTSIZE	MAX_BODYSIZE	/* XXX: + IP_HDR + ETH_HDR */

/* compact timestamp to fit into 60 byte packet. (enough to obtain RTT) */
struct tstamp {
	uint32_t sec;
	uint32_t nsec;
};

/*
 * global arguments for all threads
 */

struct glob_arg {
	struct ip_range src_ip;
	struct ip_range dst_ip;
	struct mac_range dst_mac;
	struct mac_range src_mac;
	int pkt_size;
	int burst;
	int forever;
	int npackets;	/* total packets to send */
	int frags;	/* fragments per packet */
	int nthreads;
	int cpus;
	int options;	/* testing */
#define OPT_PREFETCH	1
#define OPT_ACCESS	2
#define OPT_COPY	4
#define OPT_MEMCPY	8
#define OPT_TS		16	/* add a timestamp */
#define OPT_INDIRECT	32	/* use indirect buffers, tx only */
#define OPT_DUMP	64	/* dump rx/tx traffic */
#define OPT_MONITOR_TX  128
#define OPT_MONITOR_RX  256
	int dev_type;
#ifndef NO_PCAP
	pcap_t *p;
#endif

	int tx_rate;
	struct timespec tx_period;

	int affinity;
	int main_fd;
	struct nm_desc *nmd;
	int report_interval;		/* milliseconds between prints */
	void *(*td_body)(void *);
	void *mmap_addr;
	char ifname[MAX_IFNAMELEN];
	char *nmr_config;
	int dummy_send;
	int virt_header;	/* send also the virt_header */
	int extra_bufs;		/* goes in nr_arg3 */
	uint8_t proto;
	char* pcap_file;
	uint8_t mode;
	//uint8_t proto_read;
};

enum dev_type { DEV_NONE, DEV_NETMAP, DEV_PCAP, DEV_TAP };

/*
 * Arguments for a new thread. The same structure is used by
 * the source and the sink
 */
struct targ {
	struct glob_arg *g;
	int used;
	int completed;
	int cancel;
	int fd;
	struct nm_desc *nmd;
	volatile uint64_t count;
	struct timespec tic, toc;
	int me;
	pthread_t thread;
	int affinity;


	struct pkt_udp pkt_udp;
	struct pkt_icmp pkt_icmp;

};

#ifdef __linux__
#define sockaddr_dl    sockaddr_ll
#define sdl_family     sll_family
#define AF_LINK        AF_PACKET
#define LLADDR(s)      s->sll_addr;
#include <linux/if_tun.h>
#define TAP_CLONEDEV	"/dev/net/tun"
#endif /* __linux__ */

#ifdef __FreeBSD__
#include <net/if_tun.h>
#define TAP_CLONEDEV	"/dev/tap"
#endif /* __FreeBSD */

#ifdef __APPLE__
// #warning TAP not supported on apple ?
#include <net/if_utun.h>
#define TAP_CLONEDEV	"/dev/tap"
#endif /* __APPLE__ */

#define	PAY_OFS	42	/* where in the pkt... */

#define R_PCAP 3

#define ALL_PROTO 18

#define GEN 2 

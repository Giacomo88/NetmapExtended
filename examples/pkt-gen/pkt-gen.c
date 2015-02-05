/*
 * Copyright (C) 2011-2014 Matteo Landi, Luigi Rizzo. All rights reserved.
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * $FreeBSD: head/tools/tools/netmap/pkt-gen.c 231198 2012-02-08 11:43:29Z luigi $
 * $Id: pkt-gen.c 12346 2013-06-12 17:36:25Z luigi $
 *
 * Example program to show how to build a multithreaded packet
 * source/sink using the netmap device.
 *
 * In this example we create a programmable number of threads
 * to take care of all the queues of the interface used to
 * send or receive traffic.
 *
 */

#include "everything.h"
#include "main_thread.h"
#include "start_threads.h"
#include "sender.h"
#include "receiver.h"
#include "ping.h"
#include "pong.h"
#include "udp_packet.h"
#include "icmp_packet.h"

int verbose = 0;
/*
 * extract the extremes from a range of ipv4 addresses.
 * addr_lo[-addr_hi][:port_lo[-port_hi]]
 */
static void
extract_ip_range(struct ip_range *r)
{
	char *ap, *pp;
	struct in_addr a;

	if (verbose)
		D("extract IP range from %s", r->name);
	r->port0 = r->port1 = 0;
	r->start = r->end = 0;

	/* the first - splits start/end of range */
	ap = index(r->name, '-');	/* do we have ports ? */
	if (ap) {
		*ap++ = '\0';
	}
	/* grab the initial values (mandatory) */
	pp = index(r->name, ':');
	if (pp) {
		*pp++ = '\0';
		r->port0 = r->port1 = strtol(pp, NULL, 0);
	};
	inet_aton(r->name, &a);
	r->start = r->end = ntohl(a.s_addr);
	if (ap) {
		pp = index(ap, ':');
		if (pp) {
			*pp++ = '\0';
			if (*pp)
				r->port1 = strtol(pp, NULL, 0);
		}
		if (*ap) {
			inet_aton(ap, &a);
			r->end = ntohl(a.s_addr);
		}
	}
	if (r->port0 > r->port1) {
		uint16_t tmp = r->port0;
		r->port0 = r->port1;
		r->port1 = tmp;
	}
	if (r->start > r->end) {
		uint32_t tmp = r->start;
		r->start = r->end;
		r->end = tmp;
	}
	{
		struct in_addr a;
		char buf1[16]; // one ip address

		a.s_addr = htonl(r->end);
		strncpy(buf1, inet_ntoa(a), sizeof(buf1));
		a.s_addr = htonl(r->start);
		if (1)
			D("range is %s:%d to %s:%d",
					inet_ntoa(a), r->port0, buf1, r->port1);
	}
}

static void
extract_mac_range(struct mac_range *r)
{
	if (verbose)
		D("extract MAC range from %s", r->name);
	bcopy(ether_aton(r->name), &r->start, 6);
	bcopy(ether_aton(r->name), &r->end, 6);
#if 0
	bcopy(targ->src_mac, eh->ether_shost, 6);
	p = index(targ->g->src_mac, '-');
	if (p)
		targ->src_mac_range = atoi(p+1);

	bcopy(ether_aton(targ->g->dst_mac), targ->dst_mac, 6);
	bcopy(targ->dst_mac, eh->ether_dhost, 6);
	p = index(targ->g->dst_mac, '-');
	if (p)
		targ->dst_mac_range = atoi(p+1);
#endif
	if (verbose)
		D("%s starts at %s", r->name, ether_ntoa(&r->start));
}

struct targ *targs;
static int global_nthreads;

/* control-C handler */
static void
sigint_h(int sig)
{
	int i;

	(void)sig;	/* UNUSED */
	for (i = 0; i < global_nthreads; i++) {
		targs[i].cancel = 1;
	}
	signal(SIGINT, SIG_DFL);
}

/* sysctl wrapper to return the number of active CPUs */
static int
system_ncpus(void)
{
	int ncpus;
#if defined (__FreeBSD__)
	int mib[2] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(mib);
	sysctl(mib, 2, &ncpus, &len, NULL, 0);
#elif defined(linux)
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
#else /* others */
	ncpus = 1;
#endif /* others */
	return (ncpus);
}

/*
 * parse the vale configuration in conf and put it in nmr.
 * Return the flag set if necessary.
 * The configuration may consist of 0 to 4 numbers separated
 * by commas: #tx-slots,#rx-slots,#tx-rings,#rx-rings.
 * Missing numbers or zeroes stand for default values.
 * As an additional convenience, if exactly one number
 * is specified, then this is assigned to both #tx-slots and #rx-slots.
 * If there is no 4th number, then the 3rd is assigned to both #tx-rings
 * and #rx-rings.
 */
int
parse_nmr_config(const char* conf, struct nmreq *nmr)
{
	char *w, *tok;
	int i, v;

	nmr->nr_tx_rings = nmr->nr_rx_rings = 0;
	nmr->nr_tx_slots = nmr->nr_rx_slots = 0;
	if (conf == NULL || ! *conf)
		return 0;
	w = strdup(conf);
	for (i = 0, tok = strtok(w, ","); tok; i++, tok = strtok(NULL, ",")) {
		v = atoi(tok);
		switch (i) {
		case 0:
			nmr->nr_tx_slots = nmr->nr_rx_slots = v;
			break;
		case 1:
			nmr->nr_rx_slots = v;
			break;
		case 2:
			nmr->nr_tx_rings = nmr->nr_rx_rings = v;
			break;
		case 3:
			nmr->nr_rx_rings = v;
			break;
		default:
			D("ignored config: %s", tok);
			break;
		}
	}
	D("txr %d txd %d rxr %d rxd %d",
			nmr->nr_tx_rings, nmr->nr_tx_slots,
			nmr->nr_rx_rings, nmr->nr_rx_slots);
	free(w);
	return (nmr->nr_tx_rings || nmr->nr_tx_slots ||
			nmr->nr_rx_rings || nmr->nr_rx_slots) ?
					NM_OPEN_RING_CFG : 0;
}


/*
 * locate the src mac address for our interface, put it
 * into the user-supplied buffer. return 0 if ok, -1 on error.
 */
static int
source_hwaddr(const char *ifname, char *buf)
{
	struct ifaddrs *ifaphead, *ifap;
	int l = sizeof(ifap->ifa_name);

	if (getifaddrs(&ifaphead) != 0) {
		D("getifaddrs %s failed", ifname);
		return (-1);
	}

	for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
		struct sockaddr_dl *sdl =
				(struct sockaddr_dl *)ifap->ifa_addr;
		uint8_t *mac;

		if (!sdl || sdl->sdl_family != AF_LINK)
			continue;
		if (strncmp(ifap->ifa_name, ifname, l) != 0)
			continue;
		mac = (uint8_t *)LLADDR(sdl);
		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
				mac[0], mac[1], mac[2],
				mac[3], mac[4], mac[5]);
		if (verbose)
			D("source hwaddr %s", buf);
		break;
	}
	freeifaddrs(ifaphead);
	return ifap ? 0 : 1;
}

static void
usage(void)
{
	const char *cmd = "pkt-gen";
	fprintf(stderr,
			"Usage:\n"
			"%s arguments\n"
			"\t--data param_name=VALUE   	parameters for packet generator: dst_ip src_ip dst-mac src-mac pcap-file\n"
			"\t--arg mode=VALUE   		available mode are: read gen\n"
			"\t-i interface			interface name\n"
			"\t-f function			tx rx ping pong\n"
			"\t-n count			number of iterations (can be 0)\n"
			"\t-t pkts_to_send		also forces tx mode\n"
			"\t-r pkts_to_receive		also forces rx mode\n"
			"\t-l pkt_size			in bytes excluding CRC\n"
			/*"\t-d dst_ip[:port[-dst_ip:port]]   single or range\n"
		"\t-s src_ip[:port[-src_ip:port]]   single or range\n"
		"\t-D dst-mac\n"
		"\t-S src-mac\n" */
			"\t-a cpu_id			use setaffinity\n"
			"\t-b burst size		testing, mostly\n"
			"\t-c cores			cores to use\n"
			"\t-p threads			processes/threads to use\n"
			"\t-T report_ms			milliseconds between reports\n"
			"\t-P				use libpcap instead of netmap\n"
			"\t-w wait_for_link_time	in seconds\n"
			"\t-R rate			in packets per second\n"
			"\t-X				dump payload\n"
			"\t-H len			add empty virtio-net-header with size 'len'\n"
			"",
			cmd);

	exit(0);
}

struct sf {
	char *key;
	void *f;
};

static struct sf func[] = {
		{ "tx",	sender_body },
		{ "rx",	receiver_body },
		{ "ping",	pinger_body },
		{ "pong",	ponger_body },
		{ NULL, NULL }
};

static int
tap_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;
	char *clonedev = TAP_CLONEDEV;

	(void)err;
	(void)dev;
	/* Arguments taken by the function:
	 *
	 * char *dev: the name of an interface (or '\0'). MUST have enough
	 *   space to hold the interface name if '\0' is passed
	 * int flags: interface flags (eg, IFF_TUN etc.)
	 */

#ifdef __FreeBSD__
	if (dev[3]) { /* tapSomething */
		static char buf[128];
		snprintf(buf, sizeof(buf), "/dev/%s", dev);
		clonedev = buf;
	}
#endif
	/* open the device */
	if( (fd = open(clonedev, O_RDWR)) < 0 ) {
		return fd;
	}
	D("%s open successful", clonedev);

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));

#ifdef linux
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (*dev) {
		/* if a device name was specified, put it in the structure; otherwise,
		 * the kernel will try to allocate the "next" device of the
		 * specified type */
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	/* try to create the device */
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		D("failed to to a TUNSETIFF: %s", strerror(errno));
		close(fd);
		return err;
	}

	/* if the operation was successful, write back the name of the
	 * interface to the variable "dev", so the caller can know
	 * it. Note that the caller MUST reserve space in *dev (see calling
	 * code below) */
	strcpy(dev, ifr.ifr_name);
	D("new name is %s", dev);
#endif /* linux */

	/* this is the special file descriptor that the caller will use to talk
	 * with the virtual interface */
	return fd;
}

/* struttura di libreria per la getopt_long
 *
 * struct option {
 * 	const char *name; //nome dell'opzione
 * 	int has_arg;	//vale 1 (o required_argument) se l'opzione richiede dei parametri, 0 (no_argument) altrimenti
 * 	int *flag;	//valore restituito dalla getopt_long quando si specifica quell'opzione
 * 	int val;	//nome alternativo con una singola lettera (ad esempio --help, -h)
 * };
 */
static struct option long_options[] = {
		{"data", required_argument, 0, 0},
		{"arg", required_argument, 0, 0},
		{0, 0, 0, 0 }
};

struct long_opt_parameter {
	char *name;		//parameter name
	void *value_loc;	//where to store the value
};

/*
//parameters of option --arg
const char *arg_param[] = {
		"mode="};
#define ARG_PARAM_SIZE 1
*/

int
main(int arc, char **argv)
{
	int i=0;

	struct glob_arg g;

	int ch;
	int wait_link = 2;
	int devqueues = 1;	/* how many device queues */
	int opt_index=0;	/* index of long options (getopt_long) */
	int index=0;
	int incorrect_param=1;	/* long option parameter validity: 1=not correct, 0=correct */

	//char *mode; 	/* parameters of long options --arg*/
	//char *param;

	bzero(&g, sizeof(g));

	g.main_fd = -1;
	g.td_body = receiver_body;
	g.report_interval = 1000;	/* report interval */
	g.affinity = -1;
	/* ip addresses can also be a range x.x.x.x-x.x.x.y */
	g.src_ip.name = "10.0.0.1";
	g.dst_ip.name = "10.1.0.1";
	g.dst_mac.name = "ff:ff:ff:ff:ff:ff";
	g.src_mac.name = NULL;
	g.pkt_size = 60;
	g.burst = 512;		// default
	g.nthreads = 1;
	g.cpus = 1;
	g.forever = 1;
	g.tx_rate = 0;
	g.frags = 1;
	g.nmr_config = "";
	g.virt_header = 0;
	g.mode = GEN;
	g.proto = "udp";
	g.blocking = "yes";

	//parameters of option --data
	struct long_opt_parameter data_param[] = {
			{ "dst_ip", &g.dst_ip.name },
			{ "src_ip", &g.src_ip.name },
			{ "dst-mac", &g.dst_mac.name },
			{ "src-mac", &g.src_mac.name },
			{ "pcap-file", &g.pcap_file },
			{ "proto", &g.proto },
			{ NULL, NULL } 
	};

	
	//parameters of option --arg
	struct long_opt_parameter arg_param[] = {
		{ "mode" , &g.mode },
		{ "blocking" , &g.blocking },
		{ NULL, NULL} 
	};

	while ( (ch = getopt_long(arc, argv,
			"a:f:F:n:i:Il:b:c:o:p:T:w:WvR:XC:H:e:m:", long_options, &opt_index)) != -1) {
		struct sf *fn;

		switch(ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;

		case 0: // LONG_OPTIONS CASE

			index = optind-1;

			while(index < arc && argv[index][0] != '-') {

				//--data case
				if(strcmp(long_options[opt_index].name, "data") == 0) {

					incorrect_param=1;

					for(i=0; data_param[i].name != NULL; i++) 
					{
						//compare parameter name in data_param with parameter specified in argv
						if(strncmp(data_param[i].name, argv[index], strlen(data_param[i].name)) == 0){
							*((uintptr_t*)(data_param[i].value_loc)) = (uintptr_t) &(argv[index][strlen(data_param[i].name)+1]);
							incorrect_param=0;
							break;
						}
					}	

					if(incorrect_param == 1)
						printf("Invalid parameter in --data option\n");
				}

				//--arg case
				if(strcmp(long_options[opt_index].name, "arg") == 0) {
					incorrect_param=1;

					for(i=0; arg_param[i].name != NULL; i++) 
					{
						//compare parameter name in data_param with parameter specified in argv
						if(strncmp(arg_param[i].name, argv[index], strlen(arg_param[i].name)) == 0){
							*((uintptr_t*)(arg_param[i].value_loc)) = (uintptr_t) &(argv[index][strlen(arg_param[i].name)+1]);
							incorrect_param=0;
							break;
						}
					}
					
					/*
					for(j=0; j<ARG_PARAM_SIZE; j++) {
						if(strstr(argv[index], arg_param[j]) != NULL) { //check validity of the parameter
							incorrect_param = 0; //parameter argv[index] exists in --arg options

							if(j==0) { //mode

								mode = &argv[index][strlen(arg_param[j])];

								if (!strcmp(mode, "null")) {
									g.mode = GEN; //packet generation
								} else if (!strncmp(mode, "read", 4)) {
									g.mode = R_PCAP; //read to pcap file
								} else if (!strncmp(mode, "gen", 3)) {
									g.mode = GEN; //packet generation
								}
							}
						}
					}*/
					if(incorrect_param == 1)
						printf("Invalid parameter in --arg option\n");
				}

				index++;
			}

			break;

		case 'n':
			g.npackets = atoi(optarg);
			break;

		case 'F':
			i = atoi(optarg);
			if (i < 1 || i > 63) {
				D("invalid frags %d [1..63], ignore", i);
				break;
			}
			g.frags = i;
			break;

			/*	case 'M':
			D("mode is %s", optarg);

			if (!strcmp(optarg, "null")) {
				g.mode = GEN; //packet generation
			} else if (!strncmp(optarg, "read", 4)) {
				g.mode = R_PCAP; //read to pcap file
			} else if (!strncmp(optarg, "gen", 3)) {
				g.mode = GEN; //packet generation
			}
			break;*/

		case 'f':
			for (fn = func; fn->key; fn++) {
				if (!strcmp(fn->key, optarg))
					break;
			}
			if (fn->key)
				g.td_body = fn->f;
			else
				D("unrecognised function %s", optarg);
			break;

		case 'o':	/* data generation options */
			g.options = atoi(optarg);
			break;

		case 'a':       /* force affinity */
			g.affinity = atoi(optarg);
			break;

		case 'i':	/* interface */
			/* a prefix of tap: netmap: or pcap: forces the mode.
			 * otherwise we guess
			 */
			D("interface is %s", optarg);
			if (strlen(optarg) > MAX_IFNAMELEN - 8) {
				D("ifname too long %s", optarg);
				break;
			}
			strcpy(g.ifname, optarg);
			if (!strcmp(optarg, "null")) {
				g.dev_type = DEV_NETMAP;
				g.dummy_send = 1;
			} else if (!strncmp(optarg, "tap:", 4)) {
				g.dev_type = DEV_TAP;
				strcpy(g.ifname, optarg + 4);
			} else if (!strncmp(optarg, "pcap:", 5)) {
				g.dev_type = DEV_PCAP;
				strcpy(g.ifname, optarg + 5);
			} else if (!strncmp(optarg, "netmap:", 7) ||
					!strncmp(optarg, "vale", 4)) {
				g.dev_type = DEV_NETMAP;
			} else if (!strncmp(optarg, "tap", 3)) {
				g.dev_type = DEV_TAP;
			} else { /* prepend netmap: */
				g.dev_type = DEV_NETMAP;
				sprintf(g.ifname, "netmap:%s", optarg);
			}
			break;

		case 'I':
			g.options |= OPT_INDIRECT;	/* XXX use indirect buffer */
			break;

		case 'l':	/* pkt_size */
			g.pkt_size = atoi(optarg);
			break;

			/*case 'd':
			g.dst_ip.name = optarg;
			break;

		case 's':
			g.src_ip.name = optarg;
			break;*/

		case 'T':	/* report interval */
			g.report_interval = atoi(optarg);
			break;

		case 'w':
			wait_link = atoi(optarg);
			break;

		case 'W': /* XXX changed default */
			g.forever = 0; /* do not exit rx even with no traffic */
			break;

		case 'b':	/* burst */
			g.burst = atoi(optarg);
			break;
		case 'c':
			g.cpus = atoi(optarg);
			break;
		case 'p':
			g.nthreads = atoi(optarg);
			break;

			/*case 'D': // destination mac
			g.dst_mac.name = optarg;
			break;

		case 'S': // source mac
			g.src_mac.name = optarg;
			break;*/
		case 'v':
			verbose++;
			break;
		case 'R':
			g.tx_rate = atoi(optarg);
			break;
		case 'X':
			g.options |= OPT_DUMP;
			break;
		case 'C':
			g.nmr_config = strdup(optarg);
			break;
		case 'H':
			g.virt_header = atoi(optarg);
			break;
		case 'e': /* extra bufs */
			g.extra_bufs = atoi(optarg);
			break;
		case 'm':
			if (strcmp(optarg, "tx") == 0) {
				g.options |= OPT_MONITOR_TX;
			} else if (strcmp(optarg, "rx") == 0) {
				g.options |= OPT_MONITOR_RX;
			} else {
				D("unrecognized monitor mode %s", optarg);
			}
			break;
		}
	}

	printf("g.src_ip: %s\n", g.src_ip.name);
	printf("g.dst_ip: %s\n", g.dst_ip.name);
	printf("g.src-mac: %s\n", g.src_mac.name);
	printf("g.dst-mac: %s\n", g.dst_mac.name);
	printf("g.pcap_file: %s\n", g.pcap_file);



	if (g.ifname == NULL) {
		D("missing ifname");
		usage();
	}

	i = system_ncpus();
	if (g.cpus < 0 || g.cpus > i) {
		D("%d cpus is too high, have only %d cpus", g.cpus, i);
		usage();
	}
	if (g.cpus == 0)
		g.cpus = i;

	if (g.pkt_size < 16 || g.pkt_size > MAX_PKTSIZE) {
		D("bad pktsize %d [16..%d]\n", g.pkt_size, MAX_PKTSIZE);
		usage();
	}

	if (g.src_mac.name == NULL) {
		static char mybuf[20] = "00:00:00:00:00:00";
		/* retrieve source mac address. */
		if (source_hwaddr(g.ifname, mybuf) == -1) {
			D("Unable to retrieve source mac");
			// continue, fail later
		}
		g.src_mac.name = mybuf;
	}
	/* extract address ranges */
	extract_ip_range(&g.src_ip);
	extract_ip_range(&g.dst_ip);
	extract_mac_range(&g.src_mac);
	extract_mac_range(&g.dst_mac);

	if(strcmp(g.mode,GEN)==0 && strcmp(g.proto, "all")==0){
		D("Please, select only one protocol for gen modality");
		usage();
	}
	if(strcmp(g.mode,R_PCAP)==0 && g.pcap_file==NULL) {
		D("Please, input a file for using read modality");
		usage();
	}
	if(strcmp(g.blocking,"no")!=0 && strcmp(g.blocking,"yes")!=0) {
		D("Invalid blocking argument, insert yes or no");
		usage();
	}



	if (g.src_ip.start != g.src_ip.end ||
			g.src_ip.port0 != g.src_ip.port1 ||
			g.dst_ip.start != g.dst_ip.end ||
			g.dst_ip.port0 != g.dst_ip.port1)
		g.options |= OPT_COPY;

	if (g.virt_header != 0 && g.virt_header != VIRT_HDR_1
			&& g.virt_header != VIRT_HDR_2) {
		D("bad virtio-net-header length");
		usage();
	}

	if (g.dev_type == DEV_TAP) {
		D("want to use tap %s", g.ifname);
		g.main_fd = tap_alloc(g.ifname);
		if (g.main_fd < 0) {
			D("cannot open tap %s", g.ifname);
			usage();
		}
#ifndef NO_PCAP
	} else if (g.dev_type == DEV_PCAP) {
		char pcap_errbuf[PCAP_ERRBUF_SIZE];

		pcap_errbuf[0] = '\0'; // init the buffer
		g.p = pcap_open_live(g.ifname, 256 /* XXX */, 1, 100, pcap_errbuf);
		if (g.p == NULL) {
			D("cannot open pcap on %s", g.ifname);
			usage();
		}
		g.main_fd = pcap_fileno(g.p);
		D("using pcap on %s fileno %d", g.ifname, g.main_fd);
#endif /* !NO_PCAP */
	} else if (g.dummy_send) { /* but DEV_NETMAP */
		D("using a dummy send routine");
	} else {
		struct nmreq base_nmd;

		bzero(&base_nmd, sizeof(base_nmd));

		parse_nmr_config(g.nmr_config, &base_nmd);
		if (g.extra_bufs) {
			base_nmd.nr_arg3 = g.extra_bufs;
		}

		/*
		 * Open the netmap device using nm_open().
		 *
		 * protocol stack and may cause a reset of the card,
		 * which in turn may take some time for the PHY to
		 * reconfigure. We do the open here to have time to reset.
		 */
		g.nmd = nm_open(g.ifname, &base_nmd, 0, NULL);
		if (g.nmd == NULL) {
			D("Unable to open %s: %s", g.ifname, strerror(errno));
			goto out;
		}
		g.main_fd = g.nmd->fd;
		D("mapped %dKB at %p", g.nmd->req.nr_memsize>>10, g.nmd->mem);

		/* get num of queues in tx or rx */
		if (g.td_body == sender_body)
			devqueues = g.nmd->req.nr_tx_rings;
		else
			devqueues = g.nmd->req.nr_rx_rings;

		/* validate provided nthreads. */
		if (g.nthreads < 1 || g.nthreads > devqueues) {
			D("bad nthreads %d, have %d queues", g.nthreads, devqueues);
			// continue, fail later
		}

		if (verbose) {
			struct netmap_if *nifp = g.nmd->nifp;
			struct nmreq *req = &g.nmd->req;

			D("nifp at offset %d, %d tx %d rx region %d",
					req->nr_offset, req->nr_tx_rings, req->nr_rx_rings,
					req->nr_arg2);
			for (i = 0; i <= req->nr_tx_rings; i++) {
				struct netmap_ring *ring = NETMAP_TXRING(nifp, i);
				D("   TX%d at 0x%p slots %d", i,
						(void *)((char *)ring - (char *)nifp), ring->num_slots);
			}
			for (i = 0; i <= req->nr_rx_rings; i++) {
				struct netmap_ring *ring = NETMAP_RXRING(nifp, i);
				D("   RX%d at 0x%p slots %d", i,
						(void *)((char *)ring - (char *)nifp), ring->num_slots);
			}
		}

		/* Print some debug information. */
		fprintf(stdout,
				"%s %s: %d queues, %d threads and %d cpus.\n",
				(g.td_body == sender_body) ? "Sending on" : "Receiving from",
						g.ifname,
						devqueues,
						g.nthreads,
						g.cpus);
		if (g.td_body == sender_body) {
			fprintf(stdout, "%s -> %s (%s -> %s)\n",
					g.src_ip.name, g.dst_ip.name,
					g.src_mac.name, g.dst_mac.name);
		}

		out:
		/* Exit if something went wrong. */
		if (g.main_fd < 0) {
			D("aborting");
			usage();
		}
	}


	if (g.options) {
		D("--- SPECIAL OPTIONS:%s%s%s%s%s\n",
				g.options & OPT_PREFETCH ? " prefetch" : "",
						g.options & OPT_ACCESS ? " access" : "",
								g.options & OPT_MEMCPY ? " memcpy" : "",
										g.options & OPT_INDIRECT ? " indirect" : "",
												g.options & OPT_COPY ? " copy" : "");
	}

	g.tx_period.tv_sec = g.tx_period.tv_nsec = 0;
	if (g.tx_rate > 0) {
		/* try to have at least something every second,
		 * reducing the burst size to some 0.01s worth of data
		 * (but no less than one full set of fragments)
		 */
		uint64_t x;
		int lim = (g.tx_rate)/300;
		if (g.burst > lim)
			g.burst = lim;
		if (g.burst < g.frags)
			g.burst = g.frags;
		x = ((uint64_t)1000000000 * (uint64_t)g.burst) / (uint64_t) g.tx_rate;
		g.tx_period.tv_nsec = x;
		g.tx_period.tv_sec = g.tx_period.tv_nsec / 1000000000;
		g.tx_period.tv_nsec = g.tx_period.tv_nsec % 1000000000;
	}
	if (g.td_body == sender_body)
		D("Sending %d packets every  %ld.%09ld s",
				g.burst, g.tx_period.tv_sec, g.tx_period.tv_nsec);
	/* Wait for PHY reset. */
	D("Wait %d secs for phy reset", wait_link);
	sleep(wait_link);
	D("Ready...");

	/* Install ^C handler. */
	global_nthreads = g.nthreads;
	signal(SIGINT, sigint_h);

	/*This calloc was originally in start_threads()*/
	targs = calloc(g.nthreads, sizeof(*targs));
	start_threads(&g, targs);
	main_thread(&g, targs);
	return 0;
}

/* end of file */

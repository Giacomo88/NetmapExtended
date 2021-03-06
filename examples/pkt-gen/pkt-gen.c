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
#include "sender.h"
#include "udp_packet.h"
#include "icmp_packet.h"
#include "pcap_reader.h"

/* functions prototype */
void main_thread(struct glob_arg *g, struct targ *targs);
void start_threads(struct glob_arg *g, struct targ *targs);
void *ponger_body(void *data);
void *pinger_body(void *data);
void *receiver_body(void *data);

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

static void
usage(void)
{
	const char *cmd = "pkt-gen";
	fprintf(stderr,
			"Usage:\n"
			"%s arguments\n"
			"\t--data param_name=VALUE   	parameters for packet generator:\n"
			"\t\tdst_ip src_ip dst-mac src-mac pcap-file pkt-size virt_header\n"
			"\t-a cpu_id			use setaffinity\n"
			"\t-b burst size		testing, mostly\n"
			"\t-C nmr_config\n"
			"\t-c cores				cores to use\n"
			"\t-e extra_bufs 		number of extra buffers\n"
			"\t-F frags				number of fragments [1-62]\n"
			"\t-f function			tx rx ping pong\n"
			"\t-g pkts_generator	(can be udp icmp pcap)\n"
			"\t-I					use indirect buffer\n"
			"\t-i interface			interface name\n"
			"\t-m monitor_mode 		can be: tx rx\n"	
			"\t-n count				number of iterations (can be 0)\n"	
			"\t-o data_gen_option\n"			
			"\t-p threads			processes/threads to use\n"
			"\t-R rate				in packets per second\n"
			"\t-T report_ms			milliseconds between reports\n"
			"\t-v					verbose\n"
			"\t-W 					do not exit rx even with no traffic\n"
			"\t-w wait_for_link_time	in seconds\n"
			"\t-X					dump payload\n"
			"",
			cmd);

	exit(0);
}

struct sf {
	char *key;
	void *f;
};

static struct sf func[] = {
		{ "tx",		sender_body },
		{ "rx",		receiver_body },
		{ "ping",	pinger_body },
		{ "pong",	ponger_body },
		{ NULL, 	NULL }
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
	if ((fd = open(clonedev, O_RDWR)) < 0 ) {
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
	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
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


/* library structure used by getopt_long
 *
 * struct option {
 * 	const char *name; //option name
 * 	int has_arg;	//1 (equivalent to required_argument) if the option require some parameters, 0 (no_argument) otherwise
 * 	int *flag;	//value returned by the getopt_long 
 * 	int val;	//alternative name for the option (i.e. --help, -h)
 * };
 */
static struct option long_options[] = {
		{ "data", required_argument, 0, 0 },
		{ 0, 0, 0, 0 }
};

int
main(int arc, char **argv)
{
	struct glob_arg g;

	int ch;
	int wait_link = 2;
	int devqueues = 1;	/* how many device queues */
	int opt_index=0;	/* index of long options (getopt_long) */
	int index=0, i=0;
	int correct_gen = 0;
	int dparam_counter = 0;
	uint64_t x;
	int lim;


	struct generator_arg p_map[] = {
			{ "udp" ,	initialize_packet_udp, 	update_addresses_udp, 	NULL },
			{ "icmp",	initialize_packet_icmp, update_addresses_icmp, 	NULL },
			{ "pcap",	initialize_reader, 		pcap_reader, 			close_reader },
			{ NULL, 	NULL, 					NULL, 					NULL }
	};

	bzero(&g, sizeof(g));
	g.verbose = 0;
	g.main_fd = -1;
	g.td_body = receiver_body;
	g.report_interval = 1000;	/* report interval */
	g.affinity = -1;
	g.burst = 512;		/* default */
	g.nthreads = 1;
	g.cpus = 1;
	g.forever = 1;
	g.tx_rate = 0;
	g.frags = 1;
	g.nmr_config = "";
	g.mode = "udp";
	g.gen_param = NULL;
	g.pkt_map = p_map;

	while ((ch = getopt_long(arc, argv,
			"a:f:F:n:i:Il:b:c:o:p:T:w:WvR:XC:e:m:g:", long_options, &opt_index)) != -1) {
		struct sf *fn;

		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;

		case 0: /* LONG_OPTIONS CASE */

			if (strcmp(long_options[opt_index].name, "data") == 0) {
				/* count the number of parameters for --data */
				for (index = optind - 1; index < arc && argv[index][0] != '-'; index++)
					dparam_counter++;

				/* allocate memory for g.data structure (array of string) */
				g.gen_param = (char **)malloc(sizeof(char *) * (dparam_counter + 1));
				i = 0;

				/* insert every paramenter in a position of g.data */
				for (index = optind - 1; index < arc && argv[index][0] != '-'; index++) {
					g.gen_param[i] = argv[index];
					i++;
				}

				/* last value*/
				g.gen_param[i] = NULL;
			}
			break;

		case 'g':
			g.mode = optarg;
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

		case 'v':
			g.verbose++;
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

	/* check generator name */
	correct_gen = 0;
	for (i = 0; p_map[i].key != NULL; i++) {
		if (strcmp(p_map[i].key, g.mode) == 0) {
			correct_gen = 1;
			break;
		}
	}
	if (correct_gen == 0) {
		D("generator %s not exists", g.mode);
		usage();
	}

	/* check interface name */
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

		pcap_errbuf[0] = '\0'; /* init the buffer */
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
			/* continue, fail later */
		}

		if (g.verbose) {
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
		lim = (g.tx_rate)/300;
		if (g.burst > lim)
			g.burst = lim;
		if (g.burst < g.frags)
			g.burst = g.frags;
		x = ((uint64_t)1000000000 * (uint64_t)g.burst) / (uint64_t) g.tx_rate;
		g.tx_period.tv_nsec = x;
		g.tx_period.tv_sec = g.tx_period.tv_nsec / 1000000000;
		g.tx_period.tv_nsec = g.tx_period.tv_nsec % 1000000000;
	}

	/* Wait for PHY reset. */
	D("Wait %d secs for phy reset", wait_link);
	sleep(wait_link);
	D("Ready...");

	/* Install ^C handler. */
	global_nthreads = g.nthreads;
	signal(SIGINT, sigint_h);

	/* This calloc was originally in start_threads() */
	targs = calloc(g.nthreads, sizeof(*targs));
	start_threads(&g, targs);
	return 0;
}

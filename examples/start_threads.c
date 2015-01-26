#include "everything.h"
#include "udp_packet.h"
#include "icmp_packet.h"
#include "receiver.h"

void
start_threads(struct glob_arg *g, struct targ *targs)
{
	int i;

	/*
	 * Now create the desired number of threads, each one
	 * using a single descriptor.
 	 */
	for (i = 0; i < g->nthreads; i++) {
		struct targ *t = &targs[i];

		bzero(t, sizeof(*t));
		t->fd = -1; /* default, with pcap */
		t->g = g;

	    if (g->dev_type == DEV_NETMAP) {
		struct nm_desc nmd = *g->nmd; /* copy, we overwrite ringid */
		uint64_t nmd_flags = 0;
		nmd.self = &nmd;

		if (g->nthreads > 1) {
			if (nmd.req.nr_flags != NR_REG_ALL_NIC) {
				D("invalid nthreads mode %d", nmd.req.nr_flags);
				continue;
			}
			nmd.req.nr_flags = NR_REG_ONE_NIC;
			nmd.req.nr_ringid = i;
		}
		/* Only touch one of the rings (rx is already ok) */
		if (g->td_body == receiver_body)
			nmd_flags |= NETMAP_NO_TX_POLL;

		/* register interface. Override ifname and ringid etc. */
		if (g->options & OPT_MONITOR_TX)
			nmd.req.nr_flags |= NR_MONITOR_TX;
		if (g->options & OPT_MONITOR_RX)
			nmd.req.nr_flags |= NR_MONITOR_RX;

		t->nmd = nm_open(t->g->ifname, NULL, nmd_flags |
			NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);
		if (t->nmd == NULL) {
			D("Unable to open %s: %s",
				t->g->ifname, strerror(errno));
			continue;
		}
		t->fd = t->nmd->fd;

	    } else {
		targs[i].fd = g->main_fd;
	    }
		t->used = 1;
		t->me = i;
		if (g->affinity >= 0) {
			if (g->affinity < g->cpus)
				t->affinity = g->affinity;
			else
				t->affinity = i % g->cpus;
		} else {
			t->affinity = -1;
		}

		if(g->mode!=R_PCAP)
		{
			/* default, init packets */
			if(g->proto == IPPROTO_UDP)
				initialize_packet_udp(t);
			else if(g->proto == IPPROTO_ICMP)
				initialize_packet_icmp(t);
		}
		if (pthread_create(&t->thread, NULL, g->td_body, t) == -1) {
			D("Unable to create thread %d: %s", i, strerror(errno));
			t->used = 0;
		}
	}
}

#include "everything.h"
#include "sender.h"

#ifndef NO_PCAP
static void
receive_pcap(u_char *user, const struct pcap_pkthdr * h,
		const u_char * bytes)
{
	int *count = (int *)user;
	(void)h;	/* UNUSED */
	(void)bytes;	/* UNUSED */
	(*count)++;
}
#endif /* !NO_PCAP */

static int
receive_packets(struct netmap_ring *ring, u_int limit, int dump)
{
	u_int cur, rx, n;

	cur = ring->cur;
	n = nm_ring_space(ring);
	if (n < limit)
		limit = n;
	for (rx = 0; rx < limit; rx++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF(ring, slot->buf_idx);

		if (dump)
			dump_payload(p, slot->len, ring, cur);

		cur = nm_ring_next(ring, cur);
	}
	ring->head = ring->cur = cur;

	return (rx);
}

void *
receiver_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	struct pollfd pfd = { .fd = targ->fd, .events = POLLIN };
	struct netmap_if *nifp;
	struct netmap_ring *rxring;
	int i;
	uint64_t received = 0;
	char buf[MAX_BODYSIZE];

	if (setaffinity(targ->thread, targ->affinity))
		goto quit;

	D("reading from %s fd %d main_fd %d",
			targ->g->ifname, targ->fd, targ->g->main_fd);
	/* unbounded wait for the first packet. */
	for (;!targ->cancel;) {
		i = poll(&pfd, 1, 1000);
		if (i > 0 && !(pfd.revents & POLLERR))
			break;
		RD(1, "waiting for initial packets, poll returns %d %d",
				i, pfd.revents);
	}
	/* main loop, exit after 1s silence */
	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->tic);
	if (targ->g->dev_type == DEV_TAP) {
		while (!targ->cancel) {
			/* XXX should we poll ? */
			if (read(targ->g->main_fd, buf, sizeof(buf)) > 0)
				targ->count++;
		}
#ifndef NO_PCAP
	} else if (targ->g->dev_type == DEV_PCAP) {
		while (!targ->cancel) {
			/* XXX should we poll ? */
			pcap_dispatch(targ->g->p, targ->g->burst, receive_pcap,
					(u_char *)&targ->count);
		}
#endif /* !NO_PCAP */
	} else {
		int dump = targ->g->options & OPT_DUMP;

		nifp = targ->nmd->nifp;
		while (!targ->cancel) {
			/* Once we started to receive packets, wait at most 1 seconds
		   before quitting. */
			if (poll(&pfd, 1, 1 * 1000) <= 0 && !targ->g->forever) {
				clock_gettime(CLOCK_REALTIME_PRECISE, &targ->toc);
				targ->toc.tv_sec -= 1; /* Subtract timeout time. */
				goto out;
			}

			if (pfd.revents & POLLERR) {
				D("poll err");
				goto quit;
			}

			for (i = targ->nmd->first_rx_ring; i <= targ->nmd->last_rx_ring; i++) {
				int m;

				rxring = NETMAP_RXRING(nifp, i);
				if (nm_ring_empty(rxring))
					continue;

				m = receive_packets(rxring, targ->g->burst, dump);
				received += m;
			}
			targ->count = received;
		}
	}

	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->toc);

	out:
	targ->completed = 1;
	targ->count = received;

	quit:
	/* reset the ``used`` flag. */
	targ->used = 0;

	return (NULL);
}

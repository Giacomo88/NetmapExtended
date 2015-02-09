#include "everything.h"

struct protocol {
	char *key;
	void *pkt_ptr;
};

/*
 * Send a packet, and wait for a response.
 * The payload (after UDP header, ofs 42) has a 4-byte sequence
 * followed by a struct timeval (or bintime?)
 */
void *
pinger_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	struct pollfd pfd = { .fd = targ->fd, .events = POLLIN };
	struct netmap_if *nifp = targ->nmd->nifp;
	int i, rx = 0, n = targ->g->npackets;
	void *frame;
	int size;
	uint32_t sent = 0;
	struct timespec ts, now, last_print;
	uint32_t count = 0, min = 1000000000, av = 0;

	struct protocol pkt_map[] = {
			{ "udp", &targ->pkt_udp },
			{ "icmp", &targ->pkt_icmp },
			{ NULL, NULL }
	};

	int idx = 0;
	while( pkt_map[idx].key != NULL ) {
		if( strcmp(pkt_map[idx].key, targ->g->mode) == 0 ) break;
		idx++;
	}

	frame = pkt_map[idx].pkt_ptr;
	frame += sizeof(struct virt_header) - targ->g->virt_header;
	size = targ->g->pkt_size + targ->g->virt_header;

	if (targ->g->nthreads > 1) {
		D("can only ping with 1 thread");
		return NULL;
	}

	clock_gettime(CLOCK_REALTIME_PRECISE, &last_print);
	now = last_print;
	while (n == 0 || (int)sent < n) {
		struct netmap_ring *ring = NETMAP_TXRING(nifp, 0);
		struct netmap_slot *slot;
		char *p;
		for (i = 0; i < 1; i++) { /* XXX why the loop for 1 pkt ? */
			slot = &ring->slot[ring->cur];
			slot->len = size;
			p = NETMAP_BUF(ring, slot->buf_idx);

			if (nm_ring_empty(ring)) {
				D("-- ouch, cannot send");
			} else {
				struct tstamp *tp;
				nm_pkt_copy(frame, p, size);
				clock_gettime(CLOCK_REALTIME_PRECISE, &ts);
				bcopy(&sent, p+42, sizeof(sent));
				tp = (struct tstamp *)(p+46);
				tp->sec = (uint32_t)ts.tv_sec;
				tp->nsec = (uint32_t)ts.tv_nsec;
				sent++;
				ring->head = ring->cur = nm_ring_next(ring, ring->cur);
			}
		}
		/* should use a parameter to decide how often to send */
		if (poll(&pfd, 1, 3000) <= 0) {
			D("poll error/timeout on queue %d: %s", targ->me,
					strerror(errno));
			continue;
		}
		/* see what we got back */
		for (i = targ->nmd->first_tx_ring;
				i <= targ->nmd->last_tx_ring; i++) {
			ring = NETMAP_RXRING(nifp, i);
			while (!nm_ring_empty(ring)) {
				uint32_t seq;
				struct tstamp *tp;
				slot = &ring->slot[ring->cur];
				p = NETMAP_BUF(ring, slot->buf_idx);

				clock_gettime(CLOCK_REALTIME_PRECISE, &now);
				bcopy(p+42, &seq, sizeof(seq));
				tp = (struct tstamp *)(p+46);
				ts.tv_sec = (time_t)tp->sec;
				ts.tv_nsec = (long)tp->nsec;
				ts.tv_sec = now.tv_sec - ts.tv_sec;
				ts.tv_nsec = now.tv_nsec - ts.tv_nsec;
				if (ts.tv_nsec < 0) {
					ts.tv_nsec += 1000000000;
					ts.tv_sec--;
				}
				if (1) D("seq %d/%d delta %d.%09d", seq, sent,
						(int)ts.tv_sec, (int)ts.tv_nsec);
				if (ts.tv_nsec < (int)min)
					min = ts.tv_nsec;
				count ++;
				av += ts.tv_nsec;
				ring->head = ring->cur = nm_ring_next(ring, ring->cur);
				rx++;
			}
		}
		//D("tx %d rx %d", sent, rx);
		//usleep(100000);
		ts.tv_sec = now.tv_sec - last_print.tv_sec;
		ts.tv_nsec = now.tv_nsec - last_print.tv_nsec;
		if (ts.tv_nsec < 0) {
			ts.tv_nsec += 1000000000;
			ts.tv_sec--;
		}
		if (ts.tv_sec >= 1) {
			D("count %d min %d av %d",
					count, min, av/count);
			count = 0;
			av = 0;
			min = 100000000;
			last_print = now;
		}
	}
	return NULL;
}

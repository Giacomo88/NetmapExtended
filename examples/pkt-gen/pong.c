#include "everything.h"

/*
 * reply to ping requests
 */
void *
ponger_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	struct pollfd pfd = { .fd = targ->fd, .events = POLLIN };
	struct netmap_if *nifp = targ->nmd->nifp;
	struct netmap_ring *txring, *rxring;
	int i, rx = 0, sent = 0, n = targ->g->npackets;

	if (targ->g->nthreads > 1) {
		D("can only reply ping with 1 thread");
		return NULL;
	}
	D("understood ponger %d but don't know how to do it", n);
	while (n == 0 || sent < n) {
		uint32_t txcur, txavail;
		/* #define BUSYWAIT */
#ifdef BUSYWAIT
		ioctl(pfd.fd, NIOCRXSYNC, NULL);
#else
		if (poll(&pfd, 1, 1000) <= 0) {
			D("poll error/timeout on queue %d: %s", targ->me,
					strerror(errno));
			continue;
		}
#endif
		txring = NETMAP_TXRING(nifp, 0);
		txcur = txring->cur;
		txavail = nm_ring_space(txring);
		/* see what we got back */
		for (i = targ->nmd->first_rx_ring; i <= targ->nmd->last_rx_ring; i++) {
			rxring = NETMAP_RXRING(nifp, i);
			while (!nm_ring_empty(rxring)) {
				uint16_t *spkt, *dpkt;
				uint32_t cur = rxring->cur;
				struct netmap_slot *slot = &rxring->slot[cur];
				char *src, *dst;
				src = NETMAP_BUF(rxring, slot->buf_idx);
				/* D("got pkt %p of size %d", src, slot->len); */
				rxring->head = rxring->cur = nm_ring_next(rxring, cur);
				rx++;
				if (txavail == 0)
					continue;
				dst = NETMAP_BUF(txring,
						txring->slot[txcur].buf_idx);
				/* copy... */
				dpkt = (uint16_t *)dst;
				spkt = (uint16_t *)src;
				nm_pkt_copy(src, dst, slot->len);
				dpkt[0] = spkt[3];
				dpkt[1] = spkt[4];
				dpkt[2] = spkt[5];
				dpkt[3] = spkt[0];
				dpkt[4] = spkt[1];
				dpkt[5] = spkt[2];
				txring->slot[txcur].len = slot->len;
				/* XXX swap src dst mac */
				txcur = nm_ring_next(txring, txcur);
				txavail--;
				sent++;
			}
		}
		txring->head = txring->cur = txcur;
		targ->count = sent;
#ifdef BUSYWAIT
		ioctl(pfd.fd, NIOCTXSYNC, NULL);
#endif
		/* D("tx %d rx %d", sent, rx); */
	}
	return NULL;
}

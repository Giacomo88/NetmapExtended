#include "everything.h"

uint8_t proto_idx;

static __inline struct timespec
timespec_add(struct timespec a, struct timespec b)
{
	struct timespec ret = { a.tv_sec + b.tv_sec, a.tv_nsec + b.tv_nsec };
	if (ret.tv_nsec >= 1000000000) {
		ret.tv_sec++;
		ret.tv_nsec -= 1000000000;
	}
	return ret;
}

static __inline struct timespec
timespec_sub(struct timespec a, struct timespec b)
{
	struct timespec ret = { a.tv_sec - b.tv_sec, a.tv_nsec - b.tv_nsec };
	if (ret.tv_nsec < 0) {
		ret.tv_sec--;
		ret.tv_nsec += 1000000000;
	}
	return ret;
}

/*
 * wait until ts, either busy or sleeping if more than 1ms.
 * Return wakeup time.
 */
static struct timespec
wait_time(struct timespec ts)
{
	for (;;) {
		struct timespec w, cur;
		clock_gettime(CLOCK_REALTIME_PRECISE, &cur);
		w = timespec_sub(ts, cur);
		if (w.tv_sec < 0)
			return cur;
		else if (w.tv_sec > 0 || w.tv_nsec > 1000000)
			poll(NULL, 0, 1);
	}
}

#ifdef __APPLE__
static inline void CPU_ZERO(cpuset_t *p)
{
	*p = 0;
}

static inline void CPU_SET(uint32_t i, cpuset_t *p)
{
	*p |= 1<< (i & 0x3f);
}
#endif  /* __APPLE__ */

/* set the thread affinity. */
int
setaffinity(pthread_t me, int i)
{
	cpuset_t cpumask;

	if (i == -1)
		return 0;

	/* Set thread affinity affinity.*/
	CPU_ZERO(&cpumask);
	CPU_SET(i, &cpumask);

	if (pthread_setaffinity_np(me, sizeof(cpuset_t), &cpumask) != 0) {
		D("Unable to set affinity: %s", strerror(errno));
		return 1;
	}
	return 0;
}

/* Check the payload of the packet for errors (use it for debug).
 * Look for consecutive ascii representations of the size of the packet.
 */
void
dump_payload(char *p, int len, struct netmap_ring *ring, int cur)
{
	char buf[128];
	int i, j, i0;

	/* get the length in ASCII of the length of the packet. */

	printf("ring %p cur %5d [buf %6d flags 0x%04x len %5d]\n",
			ring, cur, ring->slot[cur].buf_idx,
			ring->slot[cur].flags, len);
	/* hexdump routine */
	for (i = 0; i < len; ) {
		memset(buf, sizeof(buf), ' ');
		sprintf(buf, "%5d: ", i);
		i0 = i;
		for ( j = 0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j*3, "%02x ", (uint8_t)(p[i]));
		i = i0;
		for ( j = 0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j + 48, "%c",
					isprint(p[i]) ? p[i] : '.');
		printf("%s\n", buf);
	}
}

static int
send_packets(struct netmap_ring *ring, void *frame,
		int size, struct glob_arg *g, u_int count, int options,
		u_int nfrags)
{

	u_int n, sent, cur = ring->cur;
	u_int fcnt;
	void (*ptrf) (void *pkt, struct glob_arg *g);
	ptrf = g->pkt_map[proto_idx].f_update;

	n = nm_ring_space(ring);
	if (n < count)
		count = n;
	if (count < nfrags) {
		D("truncating packet, no room for frags %d %d",
				count, nfrags);
	}
#if 0
	if (options & (OPT_COPY | OPT_PREFETCH)) {
		for (sent = 0; sent < count; sent++) {
			struct netmap_slot *slot = &ring->slot[cur];
			char *p = NETMAP_BUF(ring, slot->buf_idx);

			__builtin_prefetch(p);
			cur = nm_ring_next(ring, cur);
		}
		cur = ring->cur;
	}
#endif
	for (fcnt = nfrags, sent = 0; sent < count; sent++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF(ring, slot->buf_idx);
		slot->flags = 0;
		slot->len = size;

		if (options & OPT_INDIRECT) {
			slot->flags |= NS_INDIRECT;
			slot->ptr = (uint64_t)((uintptr_t)frame);
		} else if (options & OPT_COPY) {

			nm_pkt_copy(frame, p, size);
			if (fcnt == nfrags) {

				ptrf(&frame, g);
				size = g->pkt_size;

			}
		} else if (options & OPT_MEMCPY) {

			memcpy(p, frame, size);
			if (fcnt == nfrags) {

				ptrf(&frame, g);
				size = g->pkt_size;

			}
		} else if (options & OPT_PREFETCH) {
			__builtin_prefetch(p);
		}
		if (options & OPT_DUMP)
			dump_payload(p, size, ring, cur);

		if (--fcnt > 0)
			slot->flags |= NS_MOREFRAG;
		else
			fcnt = nfrags;
		if (sent == count - 1) {
			slot->flags &= ~NS_MOREFRAG;
			slot->flags |= NS_REPORT;
		}
		cur = nm_ring_next(ring, cur);
	}
	ring->head = ring->cur = cur;

	return (sent);
}

void *
sender_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	struct pollfd pfd = { .fd = targ->fd, .events = POLLOUT };
	struct netmap_if *nifp;
	struct netmap_ring *txring;
	int i, n = targ->g->npackets / targ->g->nthreads;
	int64_t sent = 0;
	int options = targ->g->options | OPT_COPY;
	struct timespec nexttime = { 0, 0}; /* XXX silence compiler */
	int rate_limit = targ->g->tx_rate;

	void *frame=NULL;
	int size=0;

	/* print some information */
	if (strcmp(targ->g->mode,"pcap") != 0)
		fprintf(stdout, "%s -> %s (%s -> %s)\n",
				targ->g->src_ip.name, targ->g->dst_ip.name,
				targ->g->src_mac.name, targ->g->dst_mac.name);

	D("Sending %d packets every  %ld.%09ld s",
			targ->g->burst, targ->g->tx_period.tv_sec, targ->g->tx_period.tv_nsec);

	proto_idx = 0;
	while (targ->g->pkt_map[proto_idx].key != NULL) {
		if (strcmp(targ->g->pkt_map[proto_idx].key, targ->g->mode) == 0) {
			break;
		}
		proto_idx++;
	}

	frame = targ->packet;
	size = targ->g->pkt_size;

	void (*ptrf) (void *pkt, struct glob_arg *g);
	ptrf = targ->g->pkt_map[proto_idx].f_update;

	D("start, fd %d main_fd %d", targ->fd, targ->g->main_fd);
	if (setaffinity(targ->thread, targ->affinity))
		goto quit;

	/* main loop.*/
	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->tic);
	if (rate_limit) {
		targ->tic = timespec_add(targ->tic, (struct timespec){2,0});
		targ->tic.tv_nsec = 0;
		wait_time(targ->tic);
		nexttime = targ->tic;
	}
	if (targ->g->dev_type == DEV_TAP) {
		D("writing to file desc %d", targ->g->main_fd);

		for (i = 0; !targ->cancel && (n == 0 || sent < n); i++) {
			if (write(targ->g->main_fd, frame, size) != -1)
				sent++;

			ptrf(&frame, targ->g);
			size = targ->g->pkt_size;

			if (i > 10000) {
				targ->count = sent;
				i = 0;
			}
		}
#ifndef NO_PCAP
	} else if (targ->g->dev_type == DEV_PCAP) {
		pcap_t *p = targ->g->p;

		for (i = 0; !targ->cancel && (n == 0 || sent < n); i++) {
			if (pcap_inject(p, frame, size) != -1)
				sent++;

			ptrf(&frame, targ->g);
			size = targ->g->pkt_size;

			if (i > 10000) {
				targ->count = sent;
				i = 0;
			}
		}
#endif /* NO_PCAP */
	} else {
		int tosend = 0, m=0, limit;
		int frags = targ->g->frags;
		nifp = targ->nmd->nifp;
		while (!targ->cancel && (n == 0 || sent < n)) {

			if (rate_limit && tosend <= 0) {
				tosend = targ->g->burst;
				nexttime = timespec_add(nexttime, targ->g->tx_period);
				wait_time(nexttime);
			}

			/*
			 * wait for available room in the send queue(s)
			 */
			if (poll(&pfd, 1, 2000) <= 0) {
				if (targ->cancel)
					break;
				D("poll error/timeout on queue %d: %s", targ->me,
						strerror(errno));
				/* goto quit; */
			}
			if (pfd.revents & POLLERR) {
				D("poll error");
				goto quit;
			}
			/*
			 * scan our queues and send on those with room
			 */
			if (options & OPT_COPY && sent > 100000 && !(targ->g->options & OPT_COPY)) {
				D("drop copy");
				options &= ~OPT_COPY;
			}
			for (i = targ->nmd->first_tx_ring; i <= targ->nmd->last_tx_ring; i++) {
				m = 0;
				limit = rate_limit ?  tosend : targ->g->burst;
				if (n > 0 && n - sent < limit)
					limit = n - sent;
				txring = NETMAP_TXRING(nifp, i);
				if (nm_ring_empty(txring))
					continue;
				if (frags > 1)
					limit = ((limit + frags - 1) / frags) * frags;

				m = send_packets(txring, frame, size, targ->g,
						limit, options, frags);

				ND("limit %d tail %d frags %d m %d",
						limit, txring->tail, frags, m);
				sent += m;
				targ->count = sent;
				if (rate_limit) {
					tosend -= m;
					if (tosend <= 0)
						break;
				}
			}
		}
		/* flush any remaining packets */
		ioctl(pfd.fd, NIOCTXSYNC, NULL);

		/* final part: wait all the TX queues to be empty. */
		for (i = targ->nmd->first_tx_ring; i <= targ->nmd->last_tx_ring; i++) {
			txring = NETMAP_TXRING(nifp, i);
			while (nm_tx_pending(txring)) {
				ioctl(pfd.fd, NIOCTXSYNC, NULL);
				usleep(1); /* wait 1 tick */
			}
		}
	} /* end DEV_NETMAP */

	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->toc);
	targ->completed = 1;
	targ->count = sent;

	quit:
	/* reset the ``used`` flag. */
	targ->used = 0;

	if (targ->g->pkt_map[proto_idx].f_close != NULL) {
		void (*f_close) ();
		f_close = targ->g->pkt_map[proto_idx].f_close;
		f_close();
	}

	return (NULL);
}

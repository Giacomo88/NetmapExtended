#include "everything.h"

/* Compute the checksum of the given ip header. */
static uint16_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = data;
        uint32_t i;

        /* Checksum all the pairs of bytes first... */
        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return sum;
}

static u_int16_t
wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

/*
 * initialize one packet and prepare for the next one.
 * The copy could be done better instead of repeating it each time.
 */
void
initialize_packet_icmp(struct targ *targ)
{
	const char *default_payload="netmap pkt-gen DIRECT payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ ";

	const char *indirect_payload="netmap pkt-gen indirect payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ ";

	struct pkt_icmp *pkt = &targ->pkt_icmp;
	struct ether_header *eh;
	struct ip *ip;
	struct icmp *icmp;
	uint16_t paylen = targ->g->pkt_size - sizeof(*eh) - sizeof(struct ip); /* length of icmp header + data*/
	const char *payload = targ->g->options & OPT_INDIRECT ?
		indirect_payload : default_payload;
	int i, l0 = strlen(payload);

	/* create a nice NUL-terminated string */
	for (i = 0; i < paylen; i += l0) {
		if (l0 > paylen - i)
			l0 = paylen - i; // last round
		bcopy(payload, pkt->body + i, l0);
	}
	pkt->body[i-1] = '\0';
	ip = &pkt->ip;

	/* prepare the headers */
    ip->ip_v = IPVERSION;
    ip->ip_hl = 5;
    ip->ip_id = 0;
    ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = ntohs(targ->g->pkt_size - sizeof(*eh));
    ip->ip_id = 0;
    ip->ip_off = htons(IP_DF); /* Don't fragment */
    ip->ip_ttl = IPDEFTTL;
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_dst.s_addr = htonl(targ->g->dst_ip.start);
	ip->ip_src.s_addr = htonl(targ->g->src_ip.start);
	ip->ip_sum = wrapsum(checksum(ip, sizeof(*ip), 0));


	icmp = &pkt->icmp;
	icmp->icmp_type = 8;  // ECHO_REQUEST

    /*    udp->uh_sport = htons(targ->g->src_ip.port0);
        udp->uh_dport = htons(targ->g->dst_ip.port0);
	udp->uh_ulen = htons(paylen);
	 Magic: taken from sbin/dhclient/packet.c
	udp->uh_sum = wrapsum(checksum(udp, sizeof(*udp),
                    checksum(pkt->body,
                        paylen - sizeof(*udp),
                        checksum(&ip->ip_src, 2 * sizeof(ip->ip_src),
                            IPPROTO_UDP + (u_int32_t)ntohs(udp->uh_ulen)
                        )
                    )
                ));*/

	eh = &pkt->eh;
	bcopy(&targ->g->src_mac.start, eh->ether_shost, 6);
	bcopy(&targ->g->dst_mac.start, eh->ether_dhost, 6);
	eh->ether_type = htons(ETHERTYPE_IP);

	bzero(&pkt->vh, sizeof(pkt->vh));
	// dump_payload((void *)pkt, targ->g->pkt_size, NULL, 0);
}

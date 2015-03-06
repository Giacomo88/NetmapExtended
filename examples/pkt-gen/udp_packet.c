#include "everything.h"
#include "extract.h"

void checksumUdp(struct pkt_udp *pkt)
{
	struct ip *ip;
	struct udphdr *udp;
	uint16_t paylen;
	
	ip = &pkt->ip;
	udp = &pkt->udp;

	paylen = htons(ip->ip_len) - sizeof(struct ip);

	ip->ip_sum = 0;
	ip->ip_sum = wrapsum(checksum(ip, sizeof(*ip), 0));

	udp->uh_sum = 0;
	udp->uh_sum = wrapsum(
			checksum(udp, sizeof(*udp),
					checksum(pkt->body,	paylen - sizeof(*udp),
							checksum(&ip->ip_src, 2 * sizeof(ip->ip_src), IPPROTO_UDP + (u_int32_t)ntohs(udp->uh_ulen)
							)
					)
			));
}

/*
 * increment the addressed in the packet,
 * starting from the least significant field.
 *	DST_IP DST_PORT SRC_IP SRC_PORT
 */
void
update_addresses_udp(void **frame, struct glob_arg *g)
{
	uint32_t a;
	uint16_t p;

	/* Align the pointer to the structure pkt_udp */
	*frame = *frame - (sizeof(struct virt_header) - g->virt_header);

	struct pkt_udp *pkt = (struct pkt_udp *)*frame;
	struct ip *ip = &pkt->ip;
	struct udphdr *udp = &pkt->udp;

	do {
		p = ntohs(udp->uh_sport);

		if (p < g->src_ip.port1) { /* just inc, no wrap */
			udp->uh_sport = htons(p + 1);
			break;
		}
		udp->uh_sport = htons(g->src_ip.port0);

		a = ntohl(ip->ip_src.s_addr);
		if (a < g->src_ip.end) { /* just inc, no wrap */
			ip->ip_src.s_addr = htonl(a + 1);
			break;
		}
		ip->ip_src.s_addr = htonl(g->src_ip.start);

		udp->uh_sport = htons(g->src_ip.port0);
		p = ntohs(udp->uh_dport);
		if (p < g->dst_ip.port1) { /* just inc, no wrap */
			udp->uh_dport = htons(p + 1);
			break;
		}
		udp->uh_dport = htons(g->dst_ip.port0);

		a = ntohl(ip->ip_dst.s_addr);
		if (a < g->dst_ip.end) { /* just inc, no wrap */
			ip->ip_dst.s_addr = htonl(a + 1);
			break;
		}
		ip->ip_dst.s_addr = htonl(g->dst_ip.start);
	} while (0);

	/* update checksum */
	checksumUdp(pkt);

	*frame = *frame + (sizeof(struct virt_header) - g->virt_header);
}

/*
 * initialize one packet and prepare for the next one.
 * The copy could be done better instead of repeating it each time.
 */
int
initialize_packet_udp(struct targ *targ)
{
	const char *default_payload="netmap pkt-gen DIRECT payload\n"
			"http://info.iet.unipi.it/~luigi/netmap/ ";

	const char *indirect_payload="netmap pkt-gen indirect payload\n"
			"http://info.iet.unipi.it/~luigi/netmap/ ";

	int i, j, l0;
	struct pkt_udp *pkt;
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;
	uint16_t paylen;

	/* default value */
	/* ip addresses can also be a range x.x.x.x-x.x.x.y */
	targ->g->src_ip.name = "10.0.0.1";
	targ->g->dst_ip.name = "10.1.0.1";
	targ->g->dst_mac.name = "ff:ff:ff:ff:ff:ff";
	targ->g->src_mac.name = NULL;
	targ->g->pkt_size = 60;
	targ->g->virt_header = 0;

	/* if user enter some --data param */
	if (targ->g->gen_param != NULL) {

		/* parameters to parse */
		struct long_opt_parameter data_param[] = {
				{ "dst_ip", &targ->g->dst_ip.name, "char" },
				{ "src_ip", &targ->g->src_ip.name, "char" },
				{ "dst-mac", &targ->g->dst_mac.name, "char" },
				{ "src-mac", &targ->g->src_mac.name, "char" },
				{ "pkt-size", &targ->g->pkt_size, "int" },
				{ "virt_header", &targ->g->virt_header, "int" },
				{ NULL, NULL, NULL }
		};

		/* parse gen_param array */
		for (i = 0; targ->g->gen_param[i] != NULL; i++) {
			for (j = 0; data_param[j].name != NULL; j++) {
				if (strncmp(data_param[j].name, targ->g->gen_param[i], strlen(data_param[j].name)) == 0){
					if (strcmp(data_param[j].type, "char") == 0)
						*((uintptr_t*)(data_param[j].value_loc)) = (uintptr_t) &(targ->g->gen_param[i][strlen(data_param[j].name) + 1]);
					else /*int param use atoi*/
						*((int*)(data_param[j].value_loc)) =  (atoi(&targ->g->gen_param[i][strlen(data_param[j].name) + 1]));
					break;
				}
			}
		}

		/* free array gen param */
		free(targ->g->gen_param);
	}

	if (targ->g->pkt_size < 16 || targ->g->pkt_size > MAX_PKTSIZE) {
		D("bad pktsize %d [16..%d]\n", targ->g->pkt_size, MAX_PKTSIZE);
		return -1;
	}

	if (targ->g->src_mac.name == NULL) {
		static char mybuf[20] = "00:00:00:00:00:00";
		/* retrieve source mac address. */
		if (source_hwaddr(targ->g->ifname, mybuf, targ->g->verbose) == -1) {
			D("Unable to retrieve source mac");
			return -1;
		}
		targ->g->src_mac.name = mybuf;
	}

	/* extract address ranges */
	extract_ip_range(&targ->g->src_ip, targ->g->verbose);
	extract_ip_range(&targ->g->dst_ip, targ->g->verbose);
	extract_mac_range(&targ->g->src_mac, targ->g->verbose);
	extract_mac_range(&targ->g->dst_mac, targ->g->verbose);

	if (targ->g->src_ip.start != targ->g->src_ip.end ||
			targ->g->src_ip.port0 != targ->g->src_ip.port1 ||
			targ->g->dst_ip.start != targ->g->dst_ip.end ||
			targ->g->dst_ip.port0 != targ->g->dst_ip.port1)
		targ->g->options |= OPT_COPY;

	if (targ->g->virt_header != 0 && targ->g->virt_header != VIRT_HDR_1
			&& targ->g->virt_header != VIRT_HDR_2) {
		D("bad virtio-net-header length");
		return -1;
	}

	/* initialize the packet */
	pkt = &targ->pkt_udp;
	paylen = targ->g->pkt_size - sizeof(*eh) - sizeof(struct ip);
	const char *payload = targ->g->options & OPT_INDIRECT ?
			indirect_payload : default_payload;
	l0 = strlen(payload);

	/* create a nice NUL-terminated string */
	for (i = 0; i < paylen; i += l0) {
		if (l0 > paylen - i)
			l0 = paylen - i; /* last round */
		bcopy(payload, pkt->body + i, l0);
	}
	pkt->body[i-1] = '\0';

	/* prepare the header ip */
	ip = &pkt->ip;
	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_id = 0;
	ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = ntohs(targ->g->pkt_size - sizeof(*eh));
	ip->ip_id = 0;
	ip->ip_off = htons(IP_DF); /* Don't fragment */
	ip->ip_ttl = IPDEFTTL;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_dst.s_addr = htonl(targ->g->dst_ip.start);
	ip->ip_src.s_addr = htonl(targ->g->src_ip.start);

	/* prepare the header udp */
	udp = &pkt->udp;
	udp->uh_sport = htons(targ->g->src_ip.port0);
	udp->uh_dport = htons(targ->g->dst_ip.port0);
	udp->uh_ulen = htons(paylen);

	/* compute checksum */
	checksumUdp(pkt);

	eh = &pkt->eh;
	bcopy(&targ->g->src_mac.start, eh->ether_shost, 6);
	bcopy(&targ->g->dst_mac.start, eh->ether_dhost, 6);
	eh->ether_type = htons(ETHERTYPE_IP);

	bzero(&pkt->vh, sizeof(pkt->vh));
	/* dump_payload((void *)pkt, targ->g->pkt_size, NULL, 0); */
	targ->packet = &targ->pkt_udp;

	/* previously inside in sender and ping */
	targ->packet += sizeof(struct virt_header) - targ->g->virt_header;
	targ->g->pkt_size += targ->g->virt_header;

	return 0;
}

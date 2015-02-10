#include "everything.h"

static int verbose = 0;

/*
 * extract the extremes from a range of ipv4 addresses.
 * addr_lo[-addr_hi][:port_lo[-port_hi]]
 */
void
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

void
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


/*
 * locate the src mac address for our interface, put it
 * into the user-supplied buffer. return 0 if ok, -1 on error.
 */
int
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

#ifndef ICMP_PACKET_H
#define ICMP_PACKET_H

void update_addresses_icmp(void **frame, struct glob_arg *g);
void checksumIcmp(struct pkt_icmp *pkt);
void initialize_packet_icmp(struct targ *targ);

#endif /* ICMP_PACKET_H */

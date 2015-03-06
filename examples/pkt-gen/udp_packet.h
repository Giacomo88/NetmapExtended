#ifndef UDP_PACKET_H
#define UDP_PACKET_H

void initialize_packet_udp(struct targ *targ);
void update_addresses_udp(void **frame, struct glob_arg *g);
void checksumUdp(struct pkt_udp *pkt);

#endif /* UDP_PACKET_H */

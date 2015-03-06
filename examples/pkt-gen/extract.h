#ifndef EXTRACT_H
#define EXTRACT_H

void extract_ip_range(struct ip_range *r, int verbose);
void extract_mac_range(struct mac_range *r, int verbose);
int source_hwaddr(const char *ifname, char *buf, int verbose);

#endif /* EXTRACT_H */

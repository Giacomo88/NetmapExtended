#ifndef SENDER_H
#define SENDER_H

int setaffinity(pthread_t me, int i);
void dump_payload(char *p, int len, struct netmap_ring *ring, int cur);
void *sender_body(void *data);

#endif /* SENDER_H */

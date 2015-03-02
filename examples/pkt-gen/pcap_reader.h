#ifndef PCAP_READER_H
#define PCAP_READER_H

int initialize_reader(struct targ *targ);
void close_reader();
void pcap_reader(void **frame, struct glob_arg *g);

#endif //PCAP_READER_H

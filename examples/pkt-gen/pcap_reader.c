#include "everything.h"

static char *filename;
static pcap_t *head=NULL;

int 
initialize_reader(struct targ *targ)
{
	filename = targ->g->pcap_file;
	char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
	head = pcap_open_offline(filename, errbuf);   //call pcap library function

	if (head == NULL) {
		D("Couldn't open pcap file %s: %s\n",filename , errbuf);
		return -1;
	} else
		return 0;
}

void 
close_reader()
{
	pcap_close(head);  //close the pcap file
}

void
pcap_reader(void **frame, struct glob_arg *g)
{
	struct pcap_pkthdr header; // The header that pcap gives us
	const u_char *packet; // The actual packet
	int size_vh = sizeof(struct virt_header);
	u_char *pad = (u_char*)malloc(size_vh);
	memset(pad,0, size_vh);
	u_char *buffer=NULL;

	if(head==NULL) {
		pcap_close(head);
		char errbuf[PCAP_ERRBUF_SIZE];
		head = pcap_open_offline(filename, errbuf);   //call pcap library function

		if (head == NULL) {
			D("Couldn't open pcap file %s: %s\n",filename , errbuf);
			exit(EXIT_FAILURE);
		}
	}

	while (1) {

		if((packet = pcap_next(head,&header))==NULL) {
			pcap_close(head);
			char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
			head = pcap_open_offline(filename, errbuf);   //call pcap library function

			if (head == NULL) {
				D("Couldn't open pcap file %s: %s\n",filename , errbuf);
				exit(EXIT_FAILURE);
			}
			continue;
		}

		u_char *pkt_ptr = (u_char *)packet; //cast a pointer to the packet data

		//parse the first (ethernet) header, grabbing the type field
		int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
		int ether_offset = 0;

		if (ether_type == ETHERTYPE_IP) //most common IPv4
			ether_offset = 14;
		else
			continue; // non mi importa dei non IPV4

		struct ip *ip_hdr = (struct ip *)&pkt_ptr[ether_offset]; //point to an IP header structure

		if(ip_hdr->ip_p == IPPROTO_ICMP || ip_hdr->ip_p == IPPROTO_UDP){

			g->pkt_size = header.len;
			if(buffer!=NULL) free(buffer);
			buffer = (u_char*)malloc(g->pkt_size  + size_vh);
			memcpy(buffer,pad,size_vh);
			memcpy(buffer + size_vh, pkt_ptr, g->pkt_size );
			break;
		} else
			continue;
	}

	*frame = buffer;
	*frame += sizeof(struct virt_header) - g->virt_header;
	g->pkt_size += g->virt_header;
}
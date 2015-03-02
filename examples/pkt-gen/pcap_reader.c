#include "everything.h"

static char *filename;
static pcap_t *head = NULL;
static u_char *buffer = NULL;

void 
close_reader()
{
	free(buffer);
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

	if (head == NULL) {
		pcap_close(head);
		char errbuf[PCAP_ERRBUF_SIZE];
		head = pcap_open_offline(filename, errbuf);   //call pcap library function

		if (head == NULL) {
			D("Couldn't open pcap file %s: %s\n",filename , errbuf);
			exit(EXIT_FAILURE);
		}
	}

	while (1) {

		if ((packet = pcap_next(head,&header)) == NULL) {
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

		if (ip_hdr->ip_p == IPPROTO_ICMP || ip_hdr->ip_p == IPPROTO_UDP) {

			g->pkt_size = header.len;
			if (buffer != NULL) 
				free(buffer);
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

int
initialize_reader(struct targ *targ)
{

	/* default value */
	targ->g->pcap_file = NULL;

	/* if user enter some --data param */
	if (targ->g->gen_param != NULL) {

		int i, j;

		/* parameters to parse */
		struct long_opt_parameter data_param[] = {
				{ "pcap-file", &targ->g->pcap_file, "char" },
				{ NULL, NULL, NULL }
		};

		/* parse gen_param array */
		for (i = 0; targ->g->gen_param[i] != NULL; i++) {
			for (j = 0; data_param[j].name != NULL; j++) {
				if (strncmp(data_param[j].name, targ->g->gen_param[i], strlen(data_param[j].name)) == 0) {
					*((uintptr_t*)(data_param[j].value_loc)) = (uintptr_t) &(targ->g->gen_param[i][strlen(data_param[j].name)+1]);
					break;
				}
			}
		}

		/* free array gen param */
		free(targ->g->gen_param);
	}

	if ((filename = targ->g->pcap_file) == NULL) {
		D("Please insert a file pcap");
		return -1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];

	/* open pcap file*/
	head = pcap_open_offline(filename, errbuf);   //call pcap library function

	if (head == NULL) {
		D("Couldn't open pcap file %s: %s\n",filename , errbuf);
		return -1;
	} else {
		/* read first packet in the file */
		pcap_reader(&targ->packet, targ->g);
		return 0;
	}
}

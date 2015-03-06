#include "everything.h"

static char *filename;
static pcap_t *head = NULL;
static u_char *buffer = NULL;

void 
close_reader()
{
	free(buffer);
	pcap_close(head);
}

void
pcap_reader(void **frame, struct glob_arg *g)
{
	struct pcap_pkthdr header;
	struct ip *ip_hdr;
	const u_char *packet;
	int size_vh = sizeof(struct virt_header);
	int ether_offset = 14, ether_type;
	u_char *pkt_ptr;
	u_char *pad = (u_char*)malloc(size_vh);

	memset(pad,0, size_vh);

	/* check if the head pointer reaches the EOF */
	if (head == NULL) {

		/* closes the file associated with head and deallocates resources */
		pcap_close(head);
		char errbuf[PCAP_ERRBUF_SIZE];

		/* re-open the pcap file */
		head = pcap_open_offline(filename, errbuf);

		/* checks if there were problems in opening the file */
		if (head == NULL) {
			D("Couldn't open pcap file %s: %s\n",filename , errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* loop until it isn't read a valid packet. */
	for(;;) {

		/* read the next packet from the pcap file */
		packet = pcap_next(head,&header);

		if (packet == NULL) {

			/* close and re-open the pcap file */
			pcap_close(head);
			char errbuf[PCAP_ERRBUF_SIZE];
			head = pcap_open_offline(filename, errbuf);

			if (head == NULL) {
				D("Couldn't open pcap file %s: %s\n",filename , errbuf);
				exit(EXIT_FAILURE);
			}
			continue;
		}

		/* cast a pointer to the packet data */
		pkt_ptr = (u_char *)packet;

		/* parse the first (ethernet) header, grabbing the type field */
		ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];

		/* consider only IPv4 packets */
		if (ether_type != ETHERTYPE_IP)
			continue;

		/* point to an IP header structure */
		ip_hdr = (struct ip *)&pkt_ptr[ether_offset];

		/* consider only ICMP and UDP packets */
		if (ip_hdr->ip_p != IPPROTO_ICMP && ip_hdr->ip_p != IPPROTO_UDP)
			continue;

		g->pkt_size = header.len;

		if (buffer != NULL)
			free(buffer);
		buffer = (u_char*)malloc(g->pkt_size  + size_vh);

		memcpy(buffer,pad,size_vh);
		memcpy(buffer + size_vh, pkt_ptr, g->pkt_size );

		break;
	}

	*frame = buffer;
	*frame += sizeof(struct virt_header) - g->virt_header;
	g->pkt_size += g->virt_header;
}

int
initialize_reader(struct targ *targ)
{
	int i, j;

	/* default value */
	targ->g->pcap_file = NULL;

	/* if user enter some --data param */
	if (targ->g->gen_param != NULL) {

		/* parameters to parse */
		struct long_opt_parameter data_param[] = {
				{ "pcap-file", &targ->g->pcap_file, "char" },
				{ NULL, NULL, NULL }
		};

		/* parse gen_param array */
		for (i = 0; targ->g->gen_param[i] != NULL; i++) {
			for (j = 0; data_param[j].name != NULL; j++) {
				if (strncmp(data_param[j].name, targ->g->gen_param[i], strlen(data_param[j].name)) == 0) {
					*((uintptr_t*)(data_param[j].value_loc)) = (uintptr_t) &(targ->g->gen_param[i][strlen(data_param[j].name) + 1]);
					break;
				}
			}
		}

		/* free array gen param */
		free(targ->g->gen_param);
	}

	filename = targ->g->pcap_file;
	if (filename == NULL) {
		D("Please insert a file pcap");
		return -1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];

	/* open pcap file */
	head = pcap_open_offline(filename, errbuf);

	if (head == NULL) {
		D("Couldn't open pcap file %s: %s\n",filename , errbuf);
		return -1;
	}

	/* read first packet in the file */
	pcap_reader(&targ->packet, targ->g);
	return 0;

}

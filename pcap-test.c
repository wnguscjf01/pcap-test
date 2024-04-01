#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "ess_libnet.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
void print_mac(uint8_t* mac) {
	int i;
	for (i = 0; i < 5; i++) {
		printf("%02x:", mac[i]);
	}
	printf("%02x\n",mac[5]);
	return;
}

void print_ip(uint8_t* ip) {
	int i;
	for (i = 0; i < 3; i++) {
		printf("%u.", ip[i]);
	}
	printf("%u\n",ip[3]);
	return;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		struct libnet_ethernet_hdr* eth_hdr = packet;
		int i;

		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
			struct libnet_ipv4_hdr* ipv4_hdr = eth_hdr+1;
			if(ipv4_hdr->ip_p == IPTYPE_TCP){
				struct libnet_tcp_hdr* tcp_hdr = ipv4_hdr+1;
				
				printf("Src MAC: ");
				print_mac((uint8_t*)(&packet->eth_hdr.ether_src_mac));
				printf("Dst MAC: ");
				print_mac((uint8_t*)(&packet->eth_hdr.ether_dst_mac));
				printf("Src IP: ");
				print_ip((uint8_t*)(&packet->ip_hdr.ip_src_addr));
				printf("Dst IP: ");
				print_ip((uint8_t*)(&packet->ip_hdr.ip_dst_addr));
				printf("Src PORT: %d, Dst PORT: %d\n\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
				
				u_int16_t plen = ntohs(ipv4_hdr->total_length)-52;
				if(plen > 20) plen = 20;
				struct payload* p = tcp_hdr+1;

				printf("Payload: ");
				if(plen == 0) printf("Empty Packet!");
				else{
					for(i=0; i<plen; i++) printf("%02x", p->pay[i]);
				}
				printf("\n\n\n");
			}
		}
	}

	pcap_close(pcap);
}

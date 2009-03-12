/** Sopstat
 * This is the main file, it parses an input file
 * with the captured stream creating an output file
 * with some statistics
 **/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "constants.h"

void usage(void);
void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void parse_ip(const u_char *datagram);

int main(int argc, char* argv[]) {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        //const u_char *packet;
        //struct pcap_pkthdr header;

        // The input file is required
        if ( argc < 2 ) {
                usage();
                return INPUT_ERROR;
        }

        //Try top open the file with the pcap lybraries
        handle = pcap_open_offline(argv[1], errbuf);
        if (handle == NULL) {
                printf("[ERROR] Unable to open %s\n\t%s \n", argv[1], errbuf);
                return INPUT_ERROR;
        }

        /* Grab packet in a loop */
        pcap_dispatch(handle, 5, parse_packet, NULL);

        /* And close the session */
        pcap_close(handle);

        return NO_ERROR; 
}

void usage(void) {
        printf("Sopstat is a postprocessing tools for the analisys of a pcap capture\n USAGE:\n\t sopstat capture.pcap\n");
}

void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        
        printf("Header \n\t[timestamp]:%ld.%ld \n\t[caplen]:%d \n\t[wirelen]:%d \n", header->ts.tv_sec, header->ts.tv_usec , header->caplen, header->len);

		/* I assume that all packets are ethernet */
        const struct ether_header *ethernet; /* The ethernet header */
        ethernet = (struct ether_header*)(packet);

        /* Serialize the Ethernet header structure */
        printf("Ethernet Header \n\t[src addr]:%x:%x:%x:%x:%x:%x \n\t[dst addr]:%x \n\t[type]:%x \n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5], ethernet->ether_dhost[0], ethernet->ether_type);
        
        /* Read the ethernet payload */
        switch( ethernet->ether_type ) {
        	case ARP:
        		printf("ARP\n");
        		//Up to now I simply discard ARP packets in my statistics
        		break;
        	case IP:
        		parse_ip( (u_char*)(packet + SIZE_ETHERNET) );
        		break;
        	default:
        		printf("Unrecognized packet\n");
        		break;
        }
}

void parse_ip(const u_char *packet) {
	const struct ip *datagram; /* The IP header */
	datagram = (struct ip*)(packet);
	
	/* Serialize the header structure */
    int i;
    for (i=0; i<20; i++) {
        printf("%x ",*(packet + i) );
    }
        
	printf("IP Header\n");
	printf("\t[version]: %u\n", datagram->ip_v);
	/* header lenght isin number of 32bit word, *4 byte */
	printf("\t[header length]: %u byte\n", (datagram->ip_hl * 4) );
	printf("\t[TOS]: %u\n", datagram->ip_tos);
	printf("\t[total length]: %hu byte\n", datagram->ip_len);
	printf("\t[identification]: %hX\n", datagram->ip_id);
	printf("\t[fragment]: %hu\n", datagram->ip_off);
	printf("\t[TTL]: %hu\n", datagram->ip_ttl);
	printf("\t[protocol]: %hu\n", datagram->ip_p);
	printf("\t[checksum]: %hX\n", datagram->ip_sum);
	printf("\t[source]: %x\n", datagram->ip_src.s_addr);
	printf("\t[destination]: %x\n", datagram->ip_dst.s_addr);
}
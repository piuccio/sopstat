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
void parse_ip(const u_char *);
void parse_tcp(const u_char *);
void parse_udp(const u_char *);

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
        
        printf("Header \n");
        printf("\t[timestamp]:%ld.%ld ", header->ts.tv_sec, header->ts.tv_usec);
        printf("\n\t[caplen]:%d \n\t[wirelen]:%d \n", header->caplen, header->len);

		/* I assume that all packets are ethernet */
        const struct ether_header *ethernet; /* The ethernet header */
        ethernet = (struct ether_header*)(packet);

        /* Serialize the Ethernet header structure */
        printf("Ethernet Header \n\t[src addr]: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
        printf("\t[dst addr]: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
        printf("\t[type]: %#.4x \n", ntohs(ethernet->ether_type));
        
        /* Read the ethernet payload */
        switch( ntohs(ethernet->ether_type) ) {
        	case ETHERTYPE_ARP:
        		printf("ARP\n");
        		//Up to now I simply discard ARP packets in my statistics
        		break;
        	case ETHERTYPE_IP:
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
	
	printf("IP Header\n");
	printf("\t[version]: %u\n", datagram->ip_v);
	/* header lenght isin number of 32bit word, *4 byte */
	printf("\t[header length]: %u byte\n", (datagram->ip_hl * 4) );
	printf("\t[TOS]: 0x%hx\n", datagram->ip_tos);
	printf("\t[total length]: %hu byte\n", ntohs(datagram->ip_len));
	printf("\t[identification]: %#.4hx\n", ntohs(datagram->ip_id));
	printf("\t[fragment]: %hu\n", ntohs(datagram->ip_off));
	printf("\t[TTL]: %hu\n", datagram->ip_ttl);
	printf("\t[protocol]: %hu\n", datagram->ip_p);
	printf("\t[checksum]: %#.4hx\n", ntohs(datagram->ip_sum));
	printf("\t[source]: %#.8x\n", ntohl(datagram->ip_src.s_addr));
	printf("\t[destination]: %#.8x\n", ntohl(datagram->ip_dst.s_addr));
	
	/* Read the IP payload */
	switch( datagram->ip_p ) {
        case IPPROTO_ICMP:
        	printf("ICMP\n");
        	//I still have nothing to do with ICMP
       		break;
       	case IPPROTO_TCP:
        	parse_tcp( (u_char*)(packet + (datagram->ip_hl * 4)) );
        	break;
        case IPPROTO_UDP:
        	parse_udp( (u_char*)(packet + (datagram->ip_hl * 4)) );
        	break;
       	default:
       		printf("Unrecognized packet\n");
       		break;
	}
}

void parse_tcp(const u_char *packet) {
	printf("TCP Header\n");
	
	const struct tcphdr *payload; /* The TCP header */
	payload = (struct tcphdr*)(packet);
	
	/* ports u_int16 */
	printf("\t[src port]: %hu\n", ntohs(payload->source));
	printf("\t[dst port]: %hu\n", ntohs(payload->dest));
	/* seq, ack u_int32 */
    printf("\t[seq]: %#.8x\n", ntohl(payload->seq));
    printf("\t[ack seq]: %#.8x\n", ntohl(payload->ack_seq));
    /* flags endian managed by libraries */
    printf("\t[res1]: %hd\n", payload->res1);
    /* Header lenght in 4byte words */
    printf("\t[header length]: %hd byte\n", payload->doff*4);
    printf("\t[fin]: %hd\n", payload->fin);
    printf("\t[syn]: %hd\n", payload->syn);
    printf("\t[rst]: %hd\n", payload->rst);
    printf("\t[psh]: %hd\n", payload->psh);
    printf("\t[ack]: %hd\n", payload->ack);
    printf("\t[urg]: %hd\n", payload->urg);
    printf("\t[res2]: %hd\n", payload->res2);
	/* window, checksum, urg u_int16 */
	printf("\t[window]: %#.4hx\n", ntohs(payload->window));
	printf("\t[checksum]: %#.4hx\n", ntohs(payload->check));
	printf("\t[urg_ptr]: %hd\n", ntohs(payload->urg_ptr));
}

void parse_udp(const u_char *packet) {
	printf("UDP Header\n");
	
	const struct udphdr *payload; /* The UDP header */
	payload = (struct udphdr*)(packet);
	
	/* All u_int16 */
	printf("\t[src port]: %hu\n", ntohs(payload->source));
	printf("\t[dst port]: %hu\n", ntohs(payload->dest));
	printf("\t[length]: %hu byte\n", ntohs(payload->len));
	printf("\t[checksum]: %#.4hx\n", ntohs(payload->check));
	
	/* UDP payload */
	printf("UDP Payload\n");
	int i, len;
	len = ntohs(payload->len);
	for (i = SIZE_UDP; i<len; i++) {
		printf("%.2x ", *(packet + i));
	}
	printf("\n");
}

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
#include "packet.h"

void usage(void);
void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int parse_ip(const u_char *, struct packet_stat *);
void parse_tcp(const u_char *, struct packet_stat *);
void parse_udp(const u_char *, struct packet_stat *);

FILE* f[MAX_OPEN_FILES];
char fname[FILENAME_MAX];
u_long first_timestamp=0;
        
int main(int argc, char* argv[]) {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];

        // The input file is required
        if ( argc < 3 ) {
                usage();
                return INPUT_ERROR;
        }

        /* Try top open the file with the pcap lybraries */
        handle = pcap_open_offline(argv[1], errbuf);
        if (handle == NULL) {
                printf("[ERROR] Unable to open %s\n\t%s \n", argv[1], errbuf);
                return INPUT_ERROR;
        }
        
        /* Try to access the output path */
        //packet level statistics
        sprintf(fname, "%s/distribution_tcp.dat", argv[2]);
        f[PKT_DISTR_TCP] = fopen(fname, "w");
        if (f[PKT_DISTR_TCP] == NULL) {
        	printf("[ERROR] Unable to create %s\n", fname);
			return INPUT_ERROR;
        }
        //time level statistics
        sprintf(fname, "%s/distribution_udp.dat", argv[2]);
        f[PKT_DISTR_UDP] = fopen(fname, "w");
        if (f[PKT_DISTR_UDP] == NULL) {
        	printf("[ERROR] Unable to create %s\n", fname);
        	fclose(f[PKT_DISTR_TCP]);
			return INPUT_ERROR;
        }

        /* Grab packet in a loop */
        pcap_loop(handle, -1, parse_packet, NULL);

        /* And close the session */
        pcap_close(handle);
        fclose(f[PKT_DISTR_TCP]);
        fclose(f[PKT_DISTR_UDP]);

		printf("Operation completed successfully");
        return NO_ERROR; 
}

void usage(void) {
        printf("Sopstat is a postprocessing tools for the analisys of a pcap capture of the sopcast traffic\n");
        printf("USAGE:\n\t sopstat capture.pcap path_to_results\n");
        printf("This software will output the statistics in the specified folder\n");
}

void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        /* Structure for the relevant informations */
        struct packet_stat stat;
        int drop = FALSE;
        
        #ifdef DEBUG
        printf("Header \n");
        printf("\t[timestamp]:%ld.%ld ", header->ts.tv_sec, header->ts.tv_usec);
        printf("\n\t[caplen]:%d \n\t[wirelen]:%d \n", header->caplen, header->len);
		#endif
		
		/* Get the timestamp (relative) and the length on the wire */
		if ( first_timestamp == 0 ) {
			first_timestamp = header->ts.tv_sec;
		}
		stat.timestamp = header->ts.tv_sec - first_timestamp;
		stat.wirelen = header->len;
		
		/* I assume that all packets are ethernet */
        const struct ether_header *ethernet; /* The ethernet header */
        ethernet = (struct ether_header*)(packet);

        /* Serialize the Ethernet header structure */
        #ifdef DEBUG
        printf("Ethernet Header \n\t[src addr]: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
        printf("\t[dst addr]: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
        printf("\t[type]: %#.4x \n", ntohs(ethernet->ether_type));
        #endif
        
        /* Read the ethernet payload */
        switch( ntohs(ethernet->ether_type) ) {
        	case ETHERTYPE_ARP:
        		#ifdef DEBUG
        		printf("ARP\n");
        		#endif
        		//Up to now I simply discard ARP packets in my statistics
        		drop = TRUE;
        		break;
        	case ETHERTYPE_IP:
        		drop = parse_ip( (u_char*)(packet + SIZE_ETHERNET), &stat );
        		break;
        	default:
        		printf("Unrecognized packet at time %ld.%ld\n", header->ts.tv_sec, header->ts.tv_usec);
        		drop = TRUE;
        		break;
        }
        
		/* All the packet informations are collected */
        if ( drop ) {
        	return;
        }
        
        char serial[MAX_SERIALIZATION];
        serialize_packet( &stat, serial );
        /* Write in the packet level stats according to the type */
        switch( stat.proto ) {
        	case IPPROTO_TCP:
        		fprintf(f[PKT_DISTR_TCP], "%s\n", serial);
        		break;
        	case IPPROTO_UDP:
        		fprintf(f[PKT_DISTR_UDP], "%s\n", serial);
        		break;
        	default:
        		printf("Error in protocol representation");
        		break;
        }
}

/* Parse the IP packet
 * Return a boolean value telling if the packet should be dropped or not
 * TRUE   drop the packet
 * FALSE  keep it for statistics
 */
int parse_ip(const u_char *packet, struct packet_stat *stat) {
	const struct ip *datagram; /* The IP header */
	datagram = (struct ip*)(packet);
	
	#ifdef DEBUG
	char src[MAX_IP_ADDR], dst[MAX_IP_ADDR];
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
	/* change the addresses representation */
	iptos(ntohl(datagram->ip_src.s_addr), src);
	printf("\t[source]: %s\n", src);
	iptos(ntohl(datagram->ip_dst.s_addr), dst);
	printf("\t[destination]: %s\n", dst);
	#endif
	
	/* Save some IP informations */
	stat->src = ntohl(datagram->ip_src.s_addr);
	stat->dst = ntohl(datagram->ip_dst.s_addr);
	stat->ttl = datagram->ip_ttl;
	stat->proto = datagram->ip_p;
	stat->iplen = ntohs(datagram->ip_len) - (datagram->ip_hl * 4);
	
	/* Read the IP payload */
	switch( datagram->ip_p ) {
        case IPPROTO_ICMP:
        	#ifdef DEBUG
        	printf("ICMP, dropping\n");
        	#endif
        	//I still have nothing to do with ICMP
        	return TRUE;
       		break;
       	case IPPROTO_TCP:
        	parse_tcp( (u_char*)(packet + (datagram->ip_hl * 4)), stat );
        	break;
        case IPPROTO_UDP:
        	parse_udp( (u_char*)(packet + (datagram->ip_hl * 4)), stat );
        	break;
       	default:
       		#ifdef DEBUG
       		printf("Unrecognized packet, dropping\n");
       		#endif
       		return TRUE;
       		break;
	}
	return FALSE;
}

void parse_tcp(const u_char *packet, struct packet_stat *stat) {
	const struct tcphdr *payload; /* The TCP header */
	payload = (struct tcphdr*)(packet);
	
	/* Save port information */
	stat->src_p = ntohs(payload->source);
	stat->dst_p = ntohs(payload->dest);
	
	#ifdef DEBUG
	printf("TCP Header\n");
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
	#endif
}

void parse_udp(const u_char *packet, struct packet_stat *stat) {
	const struct udphdr *payload; /* The UDP header */
	payload = (struct udphdr*)(packet);
	
	/* Save port information */
	stat->src_p = ntohs(payload->source);
	stat->dst_p = ntohs(payload->dest);
	
	#ifdef DEBUG
	printf("UDP Header\n");
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
	#endif
}
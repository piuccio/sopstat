#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "packet.h"
#include "time.h"

boolean first_packet = true;
struct timeval first_timestamp;

/**
 * Extract all the useful informartions from the packet and return
 * TRUE  -> this is a valid packet
 * FALSE -> the packet is not relevant for the statistics
 */
boolean parse_packet(struct packet_stat *stat, const struct pcap_pkthdr *header, const u_char *packet) {
        /* Structure for the relevant informations */
        int valid = false;
        if ( first_packet ) {
			/* This is the first packet, scale the time */
			first_timestamp = header->ts;
		}
        
		/* Measures on timestamp and length */
		stat->timestamp = timeval_difference(header->ts, first_timestamp);
		stat->wirelen = header->len;
		
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
        if ( ntohs(ethernet->ether_type) == ETHERTYPE_IP ) {
			valid = parse_ip( (u_char*)(packet + SIZE_ETHERNET), stat );
        } else {
        	#ifdef DEBUG
        		printf("Unrecognized packet at time %ld.%ld\n", header->ts.tv_sec, header->ts.tv_usec);
        	#endif
        }
        
		/* All the packet informations are collected */
		if ( valid && first_packet ) {
			/* Scale the time */
			first_packet = false;
		}
		
        return valid;
}

/* Parse the IP packet
 * Return a boolean value telling the validity of the packet
 * TRUE   packet is meaningful for the statistics
 * FALSE  drop the packet
 */
boolean parse_ip(const u_char *packet, struct packet_stat *stat) {
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
        	return false;
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
       		return false;
       		break;
	}
	return true;
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

/**
 * Convert the representation of IP addresses from integers to strings
 */
void iptos(const u_int address, char *str) {
	
	int ind = address>>24;
	int ind2 = (address & 0x00ff0000)>>16;
	int ind3 = (address & 0x0000ff00)>>8;
    int ind4 = (address & 0x000000ff);
    
    sprintf(str,"%d.%d.%d.%d",ind,ind2,ind3,ind4);
    return;
}

boolean stoip(u_int *ip, char* str) {
	*ip = 0;
	char* token = NULL;
	char delim[] = ".";
	int i=3;
	
	token = strtok( str, delim );
	if ( token == NULL ) return false;
	
	// I know the number of tokens expected
	while ( token != NULL && i >= 0 ) {
		//if ( !isdigit(token) ) return false; /* this doesn't work */
		*ip = *ip + ( atoi( token ) << 8*i );
		if ( *ip == 0 ) return false; /* 0 ip means something wrong */
		token  = strtok( NULL, "." );
		i--;
	}
	if ( token != NULL ) return false; /* too many dots */
	if ( i >= 0 ) return false; /* too few dots */
	
	return true;
}

/**
 * Serialize the packet structure in a string such that it can be
 * easily written in the output statistic files
 */
void serialize_packet(const struct packet_stat *pkt, char *str) {
	/* FORMAT (gnuplot)
	 * timestamp wirelen ip_src ip_dst iplen src_p dst_p proto
	 */
	char src[MAX_IP_ADDR], dst[MAX_IP_ADDR];
	iptos( pkt->src, src);
	iptos( pkt->dst, dst);
	sprintf(str, "%lu %u %s %s %u %hu %hu %hu", pkt->timestamp, pkt->wirelen, src, dst, pkt->iplen, pkt->src_p, pkt->dst_p, pkt->proto);
}

/**
 * Copy one statistic file to another
 */
void statcopy(packet_stat *dst, packet_stat *src) {
	dst->timestamp = src->timestamp;
	dst->wirelen = src->wirelen;
	dst->src = src->src;
	dst->dst = src->dst;
	dst->ttl = src->ttl;
	dst->proto = src->proto;
	dst->src_p = src->src_p;
	dst->dst_p = src->dst_p;
	dst->iplen = src->iplen;
	dst->next = NULL;
}
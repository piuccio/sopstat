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
boolean parse_packet(struct packet_stat *stat, const struct pcap_pkthdr *header, const u_char *packet, payload_stat_container *container ) {
        /* Structure for the relevant informations */
        int valid = false;
        if ( first_packet ) {
			/* This is the first packet, scale the time */
			first_timestamp = header->ts;
		}
        
		/* Measures on timestamp and length */
		stat->timestamp = timeval_difference(header->ts, first_timestamp);
		stat->real_ts = header->ts;
		stat->wirelen = header->len;
		
		/* I assume that all packets are ethernet */
        const struct ether_header *ethernet; /* The ethernet header */
        ethernet = (struct ether_header*)(packet);

        /* Read the Ethernet payload */
        if ( ntohs(ethernet->ether_type) == ETHERTYPE_IP ) {
			valid = parse_ip( (u_char*)(packet + SIZE_ETHERNET), stat, container );
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
boolean parse_ip(const u_char *packet, struct packet_stat *stat, payload_stat_container *container ) {
	const struct ip *datagram; /* The IP header */
	datagram = (struct ip*)(packet);
	
	/* Save some IP informations */
	stat->src = ntohl(datagram->ip_src.s_addr);
	stat->dst = ntohl(datagram->ip_dst.s_addr);
	stat->proto = datagram->ip_p;
	stat->iplen = ntohs(datagram->ip_len) - (datagram->ip_hl * 4);
	
	/* Simply discard fragmented packets, I loose the tail of large pkts */
	if ( (datagram->ip_off & 0xff00) > 0 ) {
		return false;
	}
	
	/* Assume that packets are not video */
	stat->video_segment = -1;
	
	/* Read the IP payload */
	boolean valid = true;
	switch( datagram->ip_p ) {
        case IPPROTO_TCP:
        	parse_tcp( (u_char*)(packet + (datagram->ip_hl * 4)), stat );
        	break;
        case IPPROTO_UDP:
        	valid = parse_udp( (u_char*)(packet + (datagram->ip_hl * 4)), stat, container );
        	break;
       	default:
       		valid = false;
       		break;
	}
	return valid;
}

void parse_tcp(const u_char *packet, struct packet_stat *stat) {
	const struct tcphdr *payload; /* The TCP header */
	payload = (struct tcphdr*)(packet);
	
	/* Save port information */
	stat->src_p = ntohs(payload->source);
	stat->dst_p = ntohs(payload->dest);
}

boolean parse_udp(const u_char *packet, struct packet_stat *stat, payload_stat_container *container) {
	const struct udphdr *payload; /* The UDP header */
	payload = (struct udphdr*)(packet);
	
	/* Save port information */
	stat->src_p = ntohs(payload->source);
	stat->dst_p = ntohs(payload->dest);
	
	/* Exclude unwanted traffic */
	if (stat->dst_p == 42166 || stat->dst_p <= 1028 || stat->src_p <= 1024) {
		return false;
	}
	 
	/* UDP payload */
	int len;
	/* UDP length contains also headers */
	len = ntohs(payload->len) - SIZE_UDP;
	
	parse_sopcast( (u_char*)(packet + SIZE_UDP), stat, len, container);
	
	return true;
}

/**
 * Parse the UDP payload filling the informations of the stat packet
 */
void parse_sopcast(const u_char *packet, struct packet_stat *stat, int len, payload_stat_container *container) {
	/* Parse the headers */
	stat->flag = *(packet);
	if (container->flag == NULL) {
		container->flag = (payload_stat*) malloc(sizeof(payload_stat));
		container->flag->value = stat->flag;
		container->flag->num = 1;
		container->flag->next = NULL;
	} else {
		add_payload_stat(container->flag, stat->flag);
	}
	
	stat->id_peer = *(packet + 1);
	if (container->id_peer == NULL) {
		container->id_peer = (payload_stat*) malloc(sizeof(payload_stat));
		container->id_peer->value = stat->id_peer;
		container->id_peer->num = 1;
		container->id_peer->next = NULL;
	} else {
		add_payload_stat(container->id_peer, stat->id_peer);
	}
	
	stat->segments = *(packet + 2);
	if (container->segments == NULL) {
		container->segments = (payload_stat*) malloc(sizeof(payload_stat));
		container->segments->value = stat->segments;
		container->segments->num = 1;
		container->segments->next = NULL;
	} else {
		add_payload_stat(container->segments, stat->segments);
	}
	
	stat->id_stream = *(packet + 3);
	if (container->id_stream == NULL) {
		container->id_stream = (payload_stat*) malloc(sizeof(payload_stat));
		container->id_stream->value = stat->id_stream;
		container->id_stream->num = 1;
		container->id_stream->next = NULL;
	} else {
		add_payload_stat(container->id_stream, stat->id_stream);
	}
	stat->ts = (*(packet + 4)<<24) + (*(packet + 5)<<16) + (*(packet + 6)<<8) + *(packet + 7);
	
	/* Parse the segments */
	int i,j;
	int max = (stat->segments > MAX_SEGMENTS) ? MAX_SEGMENTS : stat->segments;
	int shift = 8;
	for (i=0; i<max; i++) {
		stat->type[i] = *(packet + shift);
		if (container->type == NULL) {
			container->type = (payload_stat*) malloc(sizeof(payload_stat));
			container->type->value = stat->type[i];
			container->type->num = 1;
			container->type->next = NULL;
		} else {
			add_payload_stat(container->type, stat->type[i]);
		}
		
		stat->type_flag[i] = *(packet + shift + 1);
		if (container->type_flag == NULL) {
			container->type_flag = (payload_stat*) malloc(sizeof(payload_stat));
			container->type_flag->value = stat->type_flag[i];
			container->type_flag->num = 1;
			container->type_flag->next = NULL;
		} else {
			add_payload_stat(container->type_flag, stat->type_flag[i]);
		}
		
		stat->length[i] = (*(packet + shift + 2)<<8) + *(packet + shift + 3);
		if (container->length == NULL) {
			container->length = (payload_stat*) malloc(sizeof(payload_stat));
			container->length->value = stat->length[i];
			container->length->num = 1;
			container->length->next = NULL;
		} else {
			add_payload_stat(container->length, stat->length[i]);
		}
		
		stat->sequence[i] = (*(packet + shift + 4)<<24) + (*(packet + shift + 5)<<16) + (*(packet + shift + 6)<<8) + *(packet + shift + 7);
		
		int max_p = (stat->length[i] > MAX_PAYLOAD) ? MAX_PAYLOAD : stat->length[i];
		for (j=0; j<max_p; j++) {
			stat->payload[i][j] = *(packet + shift + 8 + j);
		}
		shift += stat->length[i];
		
		/* Is this a video packet ? */
		if ( stat->type[i] == 6 && stat->type_flag[i] == 1 && stat->length[i] >= 200) {
			// Exclude also 01ffffff
			if ( stat->payload[i][1]!=0xff && stat->payload[i][2]!=0xff && stat->payload[i][3]!=0xff) {
				stat->video_segment = i;
			}
		}
	}
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
	sprintf(str, "%d %u %s %s %u %hu %hu %hu", pkt->timestamp, pkt->wirelen, src, dst, pkt->iplen, pkt->src_p, pkt->dst_p, pkt->proto);
}

/**
 * Copy one statistic file to another
 */
void statcopy(packet_stat *dst, packet_stat *src) {
	int i,j;
	dst->timestamp = src->timestamp;
	dst->wirelen = src->wirelen;
	dst->src = src->src;
	dst->dst = src->dst;
	dst->proto = src->proto;
	dst->src_p = src->src_p;
	dst->dst_p = src->dst_p;
	dst->iplen = src->iplen;
	dst->real_ts = src->real_ts;
	dst->flag = src->flag;
	dst->id_peer = src->id_peer;
	dst->segments = src->segments;
	dst->id_stream = src->id_stream;
	dst->ts = src->ts;
	for (i=0; i<MAX_SEGMENTS; i++) {
		dst->type[i] = src->type[i];
		dst->type_flag[i] = src->type_flag[i];
		dst->length[i] = src->length[i];
		dst->sequence[i] = src->sequence[i];
		for (j=0; j<MAX_PAYLOAD; j++) {
			dst->payload[i][j] = src->payload[i][j];
		}
	}
	dst->video_segment = src->video_segment;
	
	dst->next = NULL;
}
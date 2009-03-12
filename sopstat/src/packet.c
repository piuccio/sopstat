#include <stdio.h>
#include <stdlib.h>
#include "constants.h"
#include "packet.h"

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

/**
 * Serialize the packet structure in a string such that it can be
 * easily written in the output statistic files
 */
void serialize_packet(const struct packet_stat *pkt, char *str) {
	/* FORMAT (gnuplot)
	 * timestamp wirelen ip_src ip_dst iplen src_p dst_p proto ttl
	 */
	char src[MAX_IP_ADDR], dst[MAX_IP_ADDR];
	iptos( pkt->src, src);
	iptos( pkt->dst, dst);
	sprintf(str, "%lu %u %s %s %u %hu %hu %hu %hu", pkt->timestamp, pkt->wirelen, src, dst, pkt->iplen, pkt->src_p, pkt->dst_p, pkt->proto, pkt->ttl);
}
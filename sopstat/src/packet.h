#ifndef PACKET_H_
#define PACKET_H_

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
//#include "payload.h"

/* int: 10*3, short: 5*5, blank: 1*6 +margin :P */
#define MAX_SERIALIZATION 70 

typedef struct packet_stat {
	int timestamp; /* Unix time of the packet arrival */
	u_short wirelen; /* Length of the packet on the wire (all headers) */
	u_int src; /* IP source */
	u_int dst; /* IP destination */
	u_short proto; /* IP protocol field: TCP/UDP */
	u_short src_p; /* Source port */
	u_short dst_p; /* Destination port */
	u_short iplen; /* Length of the IP payload */
	struct timeval real_ts; /* The real timestamp in microseconds */
	/* Sopstat payload */
	u_short flag; /* 1B */
	u_short id_peer; /* 1B ID of the peer */
	u_short segments; /* 1B Number of segments in the message */
	u_short id_stream; /* 1B ID of the stream */
	u_int ts; /* 4B Timestamp of the message */
	/* Beginning of the segment, no more than 3 segs */
	u_short type[MAX_SEGMENTS]; /* 1B Type of message */ 
	u_short type_flag[MAX_SEGMENTS]; /* 1B Flag for the message type */
	u_short length[MAX_SEGMENTS]; /* 2B Length of the segment */
	u_short payload[MAX_SEGMENTS][MAX_PAYLOAD]; /* Segment payload */
	
	struct packet_stat* next; /* Next pointer for the list */
} packet_stat;


typedef struct payload_stat {
	u_short value;
	int num;
	struct payload_stat* next;
} payload_stat;

typedef struct payload_stat_container {
	payload_stat* flag;
	payload_stat* id_peer;
	payload_stat* segments;
	payload_stat* id_stream;
	payload_stat* type;
	payload_stat* type_flag;
	payload_stat* length;
} payload_stat_container;

/* Define the host structure */
typedef enum {upstream, downstream} direction;

/* PROTOTYPE */
void serialize_packet(const struct packet_stat *, char *);
void iptos(const u_int, char *);
boolean stoip(u_int *, char*);
boolean parse_packet(struct packet_stat *, const struct pcap_pkthdr *, const u_char *, payload_stat_container * );
boolean parse_ip(const u_char *, struct packet_stat *, payload_stat_container * );
void parse_tcp(const u_char *, struct packet_stat *);
boolean parse_udp(const u_char *, struct packet_stat *, payload_stat_container * );
void statcopy(packet_stat *, packet_stat *);
void parse_sopcast(const u_char *, struct packet_stat *, int, payload_stat_container *);

#endif /*PACKET_H_*/
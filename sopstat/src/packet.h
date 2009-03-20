#ifndef PACKET_H_
#define PACKET_H_

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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
	struct packet_stat* next; /* Next pointer for the list */
} packet_stat;


/* Define the host structure */
typedef enum {upstream, downstream} direction;

/* PROTOTYPE */
void serialize_packet(const struct packet_stat *, char *);
void iptos(const u_int, char *);
boolean stoip(u_int *, char*);
boolean parse_packet(struct packet_stat *, const struct pcap_pkthdr *, const u_char *);
boolean parse_ip(const u_char *, struct packet_stat *);
void parse_tcp(const u_char *, struct packet_stat *);
void parse_udp(const u_char *, struct packet_stat *);
void statcopy(packet_stat *, packet_stat *);

#endif /*PACKET_H_*/

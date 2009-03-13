#ifndef PACKET_H_
#define PACKET_H_

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* long: 20, int: 10*3, short: 5*6, blank: 1*8 +margin :P */
#define MAX_SERIALIZATION 95 

struct packet_stat {
	u_long timestamp; /* Unix time of the packet arrival */
	u_short wirelen; /* Length of the packet on the wire (all headers) */
	u_int src; /* IP source */
	u_int dst; /* IP destination */
	u_short ttl; /* Time to live */
	u_short proto; /* IP protocol field: TCP/UDP */
	u_short src_p; /* Source port */
	u_short dst_p; /* Destination port */
	u_short iplen; /* Length of the IP payload */
	u_int alen; /* Aggregated length, sum of sizes of packet in that time interval */
};


/* Define the host structure */
typedef enum {upstream, downstream} direction;

struct host {
	u_int ip;  /* IP of the host */
	struct packet_stat *flow;
	struct host *next;
}; 

/* PROTOTYPE */
void serialize_packet(const struct packet_stat *, char *);
void iptos(const u_int, char *);
boolean stoip(u_int *, char*);
boolean parse_packet(struct packet_stat *, const struct pcap_pkthdr *, const u_char *);
boolean parse_ip(const u_char *, struct packet_stat *);
void parse_tcp(const u_char *, struct packet_stat *);
void parse_udp(const u_char *, struct packet_stat *);


#endif /*PACKET_H_*/

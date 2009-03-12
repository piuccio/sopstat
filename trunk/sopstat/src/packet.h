#ifndef PACKET_H_
#define PACKET_H_

/* long: 20, int: 10*2, short: 5*6, blank: 1*8 +margin :P */
#define MAX_SERIALIZATION 85 

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
};


/* PROTOTYPE */
void serialize_packet(const struct packet_stat *, char *);
void iptos(const u_int, char *);

#endif /*PACKET_H_*/

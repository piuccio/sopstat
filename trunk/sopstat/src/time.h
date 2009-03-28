#ifndef TIME_H_
#define TIME_H_
#include <stdio.h>
#include <stdlib.h>
#include "constants.h"
#include "packet.h"

typedef struct time_stat {
	int ts; /* Relative timestamp */
	long size[FLOWS]; /* aggragate IPlen size */
	int pkt[FLOWS]; /* number of packets */
	int hosts[FLOWS]; /* number of host */
	int video_hosts[FLOWS]; /* number of hosts that exchange video packets*/
	int videopkt[FLOWS]; /* number of video (and data) packet */
	int videosize[FLOWS]; /* lenght of video stream */
	int discoverypkt[FLOWS]; /* number of packet to contact new peers */
	int discoverysize[FLOWS]; /* lenght of packet to contact new hosts */
	struct ip_host* hostnames[FLOWS]; /* List of the hosts found */ 
	struct time_stat* next;
	struct time_stat* last;
} time_stat;

typedef struct ip_host {
	u_long ip; /* Unsigned long ip */
	int count; /* How many time it appears */
	struct ip_host* next;
} ip_host;
 
/* PROTOTYPES */
void register_packet(time_stat *, packet_stat *, int);
void init_time_stat(time_stat *);
int print_time(time_stat *, char *);
void print_time_flow(time_stat *, int);
int timeval_difference(struct timeval, struct timeval);
boolean timeval_bigger(struct timeval, struct timeval);
boolean is_video(packet_stat *);
void register_host(u_long, time_stat *, int, boolean);
boolean is_discovery(packet_stat *);
void print_graph(char* , char* );
#endif /*TIME_H_*/

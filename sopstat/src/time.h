#ifndef TIME_H_
#define TIME_H_
#include <stdio.h>
#include <stdlib.h>
#include "constants.h"
#include "packet.h"

#define GRANULARITY 3

typedef struct time_stat {
	u_long ts; /* Relative timestamp */
	long size[FLOWS]; /* aggragate IPlen size */
	int pkt[FLOWS]; /* number of packets */
	int host[FLOWS]; /* number of host */
	struct time_stat* next;
	struct time_stat* last;
} time_stat;
 
/* PROTOTYPES */
void register_packet(time_stat *, packet_stat *, int);
void init_time_stat(time_stat *);
int print_time(time_stat *, char *);
void print_time_flow(time_stat *, int);
long timeval_difference(struct timeval a, struct timeval b);

#endif /*TIME_H_*/

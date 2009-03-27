#ifndef LISTE_H_
#define LISTE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "constants.h"
#include "packet.h"
#include "time.h"

typedef struct chisquare {
	double x;
	int num[CHISQUARE_INTERVALS];
	int total_num;
} chisquare;

typedef struct ipnode {
   u_long ip;
   u_int alen[FLOWS]; /* Aggregated length of the flow */
   char  address [MAX_IP_ADDR];
   long num[FLOWS]; /* Number of packets per stream */
   struct packet_stat* first[FLOWS];
   struct packet_stat* last[FLOWS];
   struct chisquare chi[FLOWS][MAX_PAYLOAD];
   struct chisquare globalchi[FLOWS][MAX_PAYLOAD]; /* For all the hosts */
   struct ipnode* next;
} ipnode;


void insert_stat(ipnode *, packet_stat *, int);
void insert_node(ipnode* , u_int, packet_stat *, direction);
int print(ipnode*, char * );
void print_flow(ipnode* , int);
void dump_udp_payload(ipnode* , FILE* );
void update_chisquare(ipnode* , packet_stat *, int);
void print_chisquare(ipnode* , FILE* );
void update_global_chisquare(ipnode* , packet_stat *, int);

#endif /*LISTE_H_*/

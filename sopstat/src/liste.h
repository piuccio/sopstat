#ifndef LISTE_H_
#define LISTE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "packet.h"

typedef struct ipnode {
   u_long ip;
   u_int alen[FLOWS]; /* Aggregated length of the flow */
   char  address [MAX_IP_ADDR];
   long num[FLOWS]; /* Number of packets per stream */
   struct packet_stat* first[FLOWS];
   struct packet_stat* last[FLOWS];
   struct ipnode* next;
} ipnode;

void insert_stat(ipnode *, packet_stat *, int);
void insert_node(ipnode* , u_int, packet_stat *, direction);
int print(ipnode*, char * );
void print_flow(ipnode* , int);

#endif /*LISTE_H_*/

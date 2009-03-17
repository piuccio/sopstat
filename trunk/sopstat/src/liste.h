#ifndef LISTE_H_
#define LISTE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "packet.h"

typedef struct ipnode {
   u_long ip;
   char  address [MAX_IP_ADDR];
   struct packet_stat* upTCP;
   struct packet_stat* dwTCP;
   struct packet_stat* upUDP;
   struct packet_stat* dwUDP;
   struct ipnode* next;    	
} ipnode;

void insert_stat(packet_stat *, packet_stat *);
void insert_node(ipnode* , u_int, packet_stat *, direction);
int print(ipnode*, char * );
void printdwTCP(ipnode* );
void printupTCP(ipnode* );
void printdwUDP(ipnode* );
void printupUDP(ipnode* );

#endif /*LISTE_H_*/

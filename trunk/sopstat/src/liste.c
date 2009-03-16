/* In this library we are going to define the type of the structure that
 * we will intend to use */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "packet.h"
#include "liste.h"

/**
 * Insert a statistic packet inside a list
 */
void insert_stat(packet_stat *n, packet_stat *pkt) {
		if (n->next != NULL) {
			insert_stat(n->next, pkt);
		} else {
			packet_stat* last = (packet_stat*) malloc (sizeof(packet_stat));
			last = pkt;
			last->next = NULL;
			n->next = last;
		}
		return;
}

/**
 * Insert a new node inside the structure
 * 
 * First look if the ip already exists, otherwise it creates a new one
 * and insert the passed node, containing the collected statistics  
 */
void insert_node(ipnode* n, u_int hostip, packet_stat *pkt){
	if ( n->ip == hostip ){
		/* Node existing */
		insert_stat(n->first, pkt);
	} else if (n->next != NULL){
		/* Iterate on next host. Recursive call */
		insert_node(n->next, hostip, pkt);
  	} else {
		/* Create a new ip node */
		ipnode* last = (ipnode*) malloc (sizeof(ipnode));
		last->ip = hostip;
		last->next = NULL;
		/* Add the packet stat to the first node */
		last->first = (packet_stat*) malloc (sizeof(packet_stat));
		last->first = pkt;
		last->first->next = NULL;
		/* Link it in the tree */
		n->next = last;  
	}
	return;
}

void print(ipnode* n){
	char to_print[MAX_SERIALIZATION], ip[MAX_IP_ADDR];
	if (n != NULL) {
		iptos(n->ip, ip); 
		printf("\n[HOST] : %s", ip);
		packet_stat * tmp = n->first;
		while (tmp != NULL) {
			serialize_packet(tmp, to_print);
			printf("%s\n", to_print);
			tmp = tmp->next;
		}

		if (n->next != NULL);
			//Non si potrebbe fare con un while ?
			print(n->next);
		}
	return;
}
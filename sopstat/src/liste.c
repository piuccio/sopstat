/***************************************************************************
 *   Copyright (C) 2009 by Matteo Mana                                     *
 *   matteo.mana@gmail.com                                                *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
/** 
 * This file defines the list structure that separates the network
 * flows by hosts 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "packet.h"
#include "liste.h"

/**
 * Insert a statistic packet inside a list
 * 
 * Params
 * - n : ipnode, the current host
 * - pkt : statistics for the packet
 * - flow : udp/tcp up/dw flow
 */
FILE* f[FLOWS]; 

void insert_stat(ipnode *n, packet_stat *pkt, int flow) {
	if ( n->last[flow] != NULL ) {
		//Something is already here
		packet_stat* new = (packet_stat*) malloc (sizeof(packet_stat));
		statcopy(new, pkt);
		
		//Add to the chain
		n->last[flow]->next = new;
		//Update the last in ipnode
		n->last[flow] = new;
	} else {
		//This is the first stat
		packet_stat* new = (packet_stat*) malloc (sizeof(packet_stat));
		statcopy(new, pkt);
		
		n->first[flow] = (packet_stat*) malloc (sizeof(packet_stat));
		n->last[flow] = (packet_stat*) malloc (sizeof(packet_stat));
		n->first[flow] = new;
		n->last[flow] = new;
	}
	
	/* Update the aggregate stats */
	n->alen[flow] += pkt->iplen;
	n->num[flow] += 1;
	
	return;
}

/**
 * Insert a new node inside the structure
 * 
 * First look if the ip already exists, otherwise it creates a new one
 * and insert the passed node, containing the collected statistics
 * 
 * Params
 * - n : node, pointer to the tree
 * - hostip : IP address of the other party in the communication
 * - pkt : statistics for the packet that must be stored
 * - direction : upstream / downstream    
 */
void insert_node(ipnode* n, u_int hostip, packet_stat *pkt, direction dir){
	if ( (n->ip == hostip) || (n->ip == 0)){
		//This is can be the first element of the tree
		if ( n->ip == 0 ) {
			int i;
			for (i=0; i<FLOWS; i++) {
				n->first[i] = NULL;
			    n->last[i] = NULL;
			    n->alen[i] = 0;
			    n->num[i] = 0;
			}
			n->ip = hostip;
			iptos(hostip, n->address);
			n->next = NULL;
		}
		
		//Insert the stat in the correct place
		int flow;
		if (dir == upstream) {
			flow = (pkt->proto == IPPROTO_TCP) ? tcpUP : udpUP;
		} else {
		    flow = (pkt->proto == IPPROTO_TCP) ? tcpDW : udpDW;
		}
		
		insert_stat(n, pkt, flow);
		
	} else if (n->next != NULL){
		/* Iterate on next host. Recursive call */
		insert_node(n->next, hostip, pkt, dir);
  	} else {
		/* Create a new ip node */
		ipnode* last = (ipnode*) malloc (sizeof(ipnode));
		
		last->ip = hostip;
		iptos(hostip, last->address);
		last->next = NULL;
		int i;
		for (i=0; i<FLOWS; i++) {
			last->first[i] = NULL;
			last->last[i] = NULL;
			last->alen[i] = 0;
		}
		
		/* Add the packet stat to the first node */
		n->next = last;  
		//Insert the stat in the correct place
		int flow;
		if (dir == upstream) {
			flow = (pkt->proto == IPPROTO_TCP) ? tcpUP : udpUP;
		} else {
		    flow = (pkt->proto == IPPROTO_TCP) ? tcpDW : udpDW;
		}
		
		insert_stat(last, pkt, flow);
		
	}
	return;
}

int print(ipnode *n, char * nome){
	int i;
	
	char fname[FILENAME_MAX];
	sprintf(fname, "%s/upudp.dat", nome);
	f[udpUP] = fopen(fname, "w");
	if (f[udpUP] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		return INVALID_FOLDER;
	}
	sprintf(fname, "%s/dwudp.dat", nome);
	f[udpDW] = fopen(fname, "w");
	if (f[udpDW] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(f[udpUP]);
		return INVALID_FOLDER;
	}
	sprintf(fname, "%s/uptcp.dat", nome);
	f[tcpUP] = fopen(fname, "w");
	if (f[tcpUP] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(f[udpUP]);
		fclose(f[udpDW]);
		return INVALID_FOLDER;
	}
	sprintf(fname, "%s/dwtcp.dat", nome);
	f[tcpDW] = fopen(fname, "w");
	if (f[tcpDW] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(f[udpUP]);
		fclose(f[udpDW]);
		fclose(f[tcpUP]);
		return INVALID_FOLDER;
	}
	
	for (i=0; i<FLOWS; i++) {
		print_flow(n, i);
		fclose( f[i] );
	}
	
	return 0;	
}

void print_flow(ipnode* n, int flow) {
	/* Is there something to print ? */
	if ( n->first[flow] != NULL ) {
		/* File comments */
		fprintf(f[flow], "#%s\n", n->address);
	
		char to_print[MAX_SERIALIZATION];
	
		packet_stat* p = n->first[flow];
		while ( p != NULL ) {
			serialize_packet(p, to_print);
			fprintf(f[flow], "%s\n", to_print);
		
			p = p->next;
		}
	
		fprintf(f[flow], "\n");
	}
	
	/* Iterate */
	if ( n->next != NULL ) {
		print_flow(n->next, flow);
	}
	return;
}
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
 */
void insert_stat(packet_stat *n, packet_stat *pkt) {
		if (n->next != NULL) {
			insert_stat(n->next, pkt);
		} else {
			packet_stat* last = (packet_stat*) malloc (sizeof(packet_stat));
			statcopy(last, pkt);
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
		statcopy(last->first, pkt);
		/* Link it in the tree */
		n->next = last;  
	}
	return;
}

void print(ipnode* n){
	char to_print[MAX_SERIALIZATION];
	if (n != NULL) {
		packet_stat * tmp = n->first;
		while (tmp != NULL) {
			serialize_packet(tmp, to_print);
			printf("\n%s", to_print);
			tmp = tmp->next;
		}

		if (n->next != NULL);
			print(n->next);
		}
	return;
}
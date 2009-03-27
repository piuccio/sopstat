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
		//This is the first element of the tree
		if ( n->ip == 0 ) {
			int i;
			for (i=0; i<FLOWS; i++) {
				n->first[i] = NULL;
			    n->last[i] = NULL;
			    n->alen[i] = 0;
			    n->num[i] = 0;
			    int j,k;
			    for (j=0; j<MAX_PAYLOAD; j++) {
			    	for (k=0; k<CHISQUARE_INTERVALS; k++) {
			    		n->chi[i][j].num[k] = 0;
			    		n->globalchi[i][j].num[k] = 0;
			    	}
			    	n->chi[i][j].x = 0;
			    	n->chi[i][j].total_num = 0;
			    	n->globalchi[i][j].x = 0;
			    	n->globalchi[i][j].total_num = 0;
			    }
			}
			n->ip = hostip;
			iptos(hostip, n->address);
			n->next = NULL;
		}
		
		//Insert the stat in the correct place
		int flow;
		if ( pkt->proto == IPPROTO_TCP ) {
			flow = (dir == upstream) ? tcpUP : tcpDW;
		} else {
			flow = (dir == upstream) ? udpUP : udpDW;
			/* It's a udp stream */
			insert_stat(n, pkt, udp);
			/* Chi square */
			update_chisquare(n, pkt, udp);
			update_chisquare(n, pkt, flow);
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
			int j,k;
			for (j=0; j<MAX_PAYLOAD; j++) {
				for (k=0; k<CHISQUARE_INTERVALS; k++) {
					last->chi[i][j].num[k] = 0;
				}
				last->chi[i][j].x = 0;
				last->chi[i][j].total_num = 0;
			}
		}
		
		/* Add the packet stat to the first node */
		n->next = last;  
		//Insert the stat in the correct place
		int flow;
		if ( pkt->proto == IPPROTO_TCP ) {
			flow = (dir == upstream) ? tcpUP : tcpDW;
		} else {
			flow = (dir == upstream) ? udpUP : udpDW;
			/* It's a udp stream */
			insert_stat(last, pkt, udp);
			/* Chi square */
			update_chisquare(last, pkt, udp);
			update_chisquare(last, pkt, flow);
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
	sprintf(fname, "%s/stream.dat", nome);
	f[udp] = fopen(fname, "w");
	if (f[udp] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(f[udpUP]);
		fclose(f[udpDW]);
		fclose(f[tcpUP]);
		fclose(f[tcpDW]);
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
		fprintf(f[flow], "#%s, %ld packets\n", n->address, n->num[flow]);
	
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

/* Print the udp payload of the communication between two hosts */ 
void dump_udp_payload(ipnode* tree, FILE* f) {
	ipnode* n = tree;
	while(n->next != NULL) {
		fprintf(f, "#HOST %s (%#.8lx)\n", n->address, n->ip);
		
		packet_stat* up = (packet_stat*) malloc(sizeof(packet_stat));
		packet_stat* dw = (packet_stat*) malloc(sizeof(packet_stat));
		packet_stat* st = (packet_stat*) malloc(sizeof(packet_stat));
		up = n->first[udpUP];
		dw = n->first[udpDW];
		st = n->first[udp];
		
		while ( st != NULL ) {
			fprintf(f,"%.2hx%.2hx %.2hx%.2hx %.8x %.2hx%.2hx %.4hx\n", st->flag, st->id_peer, st->segments, st->id_stream, st->ts, st->type[0], st->type_flag[0], st->length[0]);
			st = st->next;
		}
		
		n = n->next; 
	}
		/* I suspect that 5-8 is related to the time
		fprintf(f, "#UPLOAD difference\n");
		while (up->next != NULL) {
			int diff1, diff2;
			diff1 = (up->next->real_ts.tv_sec-up->real_ts.tv_sec)*1000 + (up->next->real_ts.tv_usec-up->real_ts.tv_usec)/1000;
			diff2 = ((u_int)up->next->payload[6]-(u_int)up->payload[6])*256 + (u_int)up->next->payload[7]-(u_int)up->payload[7];
			fprintf(f, "%d\n", abs(diff1 - diff2) );
			up = up->next;
		}*/
		/* See if there are some bytes that remain equal or increase
		fprintf(f, "#UPLOAD difference\n");
		while (up->next != NULL) {
			for ( i=0; i<60; i++) {
				fprintf(f,"%.2x ", abs(up->payload[i] - up->next->payload[i]) );
			}
			fprintf(f,"\n");
			up = up->next;
		}
		
		fprintf(f, "\n\n#DOWNLOAD difference\n");
		while (dw->next != NULL) {
			for ( i=0; i<60; i++) {
				fprintf(f,"%.2x ", abs(dw->payload[i] - dw->next->payload[i]));
			}
			fprintf(f,"\n");
			dw = dw->next;
		}*/
		
		/* See if there are some bytes that remain equal in the whole stream
		up = n->first[udpUP];
		dw = n->first[udpDW];
		//packet_stat* nw = (packet_stat*) malloc(sizeof(packet_stat));
		//packet_stat* nx = (packet_stat*) malloc(sizeof(packet_stat));
		while (up != NULL) {
			//Print everything until I reach the last udp pkt
			if ( timeval_bigger(up->real_ts, dw->real_ts) ) {
				//Download comes first
				//printf("Download %d\n", dw->timestamp);
				if ( dw->next == NULL) {
					//Download is over, break the cycle
					break;
				} else {
					dw = dw->next;
				}
			} else {
				//printf("Upload %d\n", up->timestamp);
				if ( up->next == NULL ) {
					//This is the last udp packet, dump remaining dw
					while ( dw != NULL ) {
						//printf("Download %d\n", dw->timestamp);
						dw = dw->next;
					}
				}
				up = up->next;
			}
		}
		*/
		/* There is some upload to print
		while ( up != NULL ) {
			//printf("Upload %d\n", up->timestamp);
			up = up->next;
		}*/
}

void update_chisquare(ipnode* n, packet_stat *s, int flow) {
	int i,j,k;
	i = (s->segments > MAX_SEGMENTS) ? MAX_SEGMENTS : s->segments; 
	for (i-=1; i>=0; i--) {
		if (s->type[i] == 6 && s->type_flag[i] == 1) {
			j = (s->length[i] > MAX_PAYLOAD) ? MAX_PAYLOAD : s->length[i];
			for (j-=1; j>=0; j--) {
				n->chi[flow][j].total_num++;
				k = (int)s->payload[i][j]*CHISQUARE_INTERVALS/255;
				n->chi[flow][j].num[k]++;
			}
		}
	}
}

/**
 * In this case I have a direction rather than a flow
 * and I can also have TCP packets
 */
void update_global_chisquare(ipnode* n, packet_stat *s, int dir) {
	int flow;
	if ( s->proto == IPPROTO_TCP ) {
		return;
	} else {
		flow = (dir == upstream) ? udpUP : udpDW;
	}
	
	int i,j,k;
	i = (s->segments > MAX_SEGMENTS) ? MAX_SEGMENTS : s->segments; 
	for (i-=1; i>=0; i--) {
		if (s->type[i] == 6 && s->type_flag[i] == 1) {
			j = (s->length[i] > MAX_PAYLOAD) ? MAX_PAYLOAD : s->length[i];
			for (j-=1; j>=0; j--) {
				n->globalchi[flow][j].total_num++;
				k = (int)s->payload[i][j]*CHISQUARE_INTERVALS/255;
				n->globalchi[flow][j].num[k]++;
				// But also in the aggregation
				n->globalchi[udp][j].total_num++;
				n->globalchi[udp][j].num[k]++;
			}
		}
	}
}

void print_chisquare(ipnode* tree, FILE* f) {
	ipnode* n = tree;
	int i,k;
	
	/* Global chi square */
	double avg,avgDW,avgUP;
	fprintf(f, "#GLOBAL_CHISQUARE\n#[byte] [interval] [udp] [udpUP] [udpDW]\n");
	for (i=0; i<MAX_PAYLOAD; i++) {
		avg = (double)n->globalchi[udp][i].total_num / CHISQUARE_INTERVALS;
		avgDW = (double)n->globalchi[udpDW][i].total_num / CHISQUARE_INTERVALS;
		avgUP = (double)n->globalchi[udpUP][i].total_num / CHISQUARE_INTERVALS;
		for (k=0; k<CHISQUARE_INTERVALS; k++) {
			/* Sum of sqr(num of samples, avg samples in an interval) / avg */
			n->globalchi[udp][i].x += (n->globalchi[udp][i].num[k] - avg)*(n->globalchi[udp][i].num[k] - avg);
			n->globalchi[udpUP][i].x += (n->globalchi[udpUP][i].num[k] - avgUP)*(n->globalchi[udpUP][i].num[k] - avgUP);
			n->globalchi[udpDW][i].x += (n->globalchi[udpDW][i].num[k] - avgDW)*(n->globalchi[udpDW][i].num[k] - avgDW);
			fprintf(f, "%d %d %d %d %d\n", i,k, n->globalchi[udp][i].num[k], n->globalchi[udpUP][i].num[k], n->globalchi[udpDW][i].num[k]);
		}
		fprintf(f, "#[byte%d] %.3f %.3f %.3f\n", i, n->globalchi[udp][i].x/avg, n->globalchi[udpUP][i].x/avgUP, n->globalchi[udpDW][i].x/avgDW);
		fprintf(f,"\n\n");
	}
	
	/* Per host chi square */
	double e,eUP,eDW;
	while (n != NULL) {
		if ( n->chi[udp][1].total_num > 200 ) {
			fprintf(f, "#CHISQUARE %s\n#[byte] [interval] [udp] [udpUP] [udpDW]\n", n->address);
			for (i=0; i<MAX_PAYLOAD; i++) {
				e = (double)n->chi[udp][i].total_num / CHISQUARE_INTERVALS;
				eUP = (double)n->chi[udpUP][i].total_num / CHISQUARE_INTERVALS;
				eDW = (double)n->chi[udpDW][i].total_num / CHISQUARE_INTERVALS;
				for (k=0; k<CHISQUARE_INTERVALS; k++) {
					/* Sum of sqr(num of samples, avg samples in an interval) / avg */
					n->chi[udp][i].x += (n->chi[udp][i].num[k] - e)*(n->chi[udp][i].num[k] - e);
					n->chi[udpUP][i].x += (n->chi[udpUP][i].num[k] - eUP)*(n->chi[udpUP][i].num[k] - eUP);
					n->chi[udpDW][i].x += (n->chi[udpDW][i].num[k] - eDW)*(n->chi[udpDW][i].num[k] - eDW);
					fprintf(f, "%d %d %d %d %d\n", i,k, n->chi[udp][i].num[k], n->chi[udpUP][i].num[k], n->chi[udpDW][i].num[k]);
				}
				fprintf(f, "#[byte%d] %.3f %.3f %.3f\n", i, n->chi[udp][i].x/e, n->chi[udpUP][i].x/eUP, n->chi[udpDW][i].x/eDW);
				fprintf(f,"\n\n");
			}
		}
		
		n = n->next;
	}
}
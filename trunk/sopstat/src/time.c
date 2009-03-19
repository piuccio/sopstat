#include <stdio.h>
#include <stdlib.h>
#include "time.h"

FILE* ft[FLOWS];
/**
 * Parse the information of a packet
 */
void register_packet(time_stat *t, packet_stat *pkt, int direction) {
	if ( t->ts / TIME_GRANULARITY == pkt->timestamp / PACKET_GRANULARITY) {
		/* This packet goes here */
		int flow;
		if (direction == upstream) {
			flow = (pkt->proto == IPPROTO_TCP) ? tcpUP : udpUP;
		} else {
		    flow = (pkt->proto == IPPROTO_TCP) ? tcpDW : udpDW;
		}
		
		t->pkt[flow]++;
		t->size[flow] += pkt->iplen;
		
	} else {
		if ( t->last == NULL ) {
			/* I only have one object I need a new structure */
			time_stat* new = (time_stat*) malloc(sizeof(time_stat));
		
			init_time_stat(new);
			new->ts = pkt->timestamp*PACKET_GRANULARITY/TIME_GRANULARITY;
		
			// Link it
			t->next = new;
			t->last = new;
		} else if ( t->last->ts * TIME_GRANULARITY < pkt->timestamp * PACKET_GRANULARITY) {
			/* Time is flowing, I need a new structure */
			time_stat* new = (time_stat*) malloc(sizeof(time_stat));
		
			init_time_stat(new);
			new->ts = pkt->timestamp*PACKET_GRANULARITY/TIME_GRANULARITY;;
		
			// Link it
			t->last->next = new;
			t->last = new;
		}
		
		/* Remember to register the packet */
		register_packet(t->last, pkt, direction);
	}
}

void init_time_stat(time_stat *timestamp) {
	int i;
	timestamp->ts = 0;
	for (i=0; i<FLOWS; i++) {
		timestamp->host[i] = 0;
		timestamp->pkt[i] = 0;
		timestamp->size[i] = 0;
	}
	timestamp->next = NULL;
	timestamp->last = NULL;
}

int print_time(time_stat *t, char * nome) {
	int i;
	
	char fname[FILENAME_MAX];
	sprintf(fname, "%s/time_upudp.dat", nome);
	ft[udpUP] = fopen(fname, "w");
	if (ft[udpUP] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		return INVALID_FOLDER;
	}
	sprintf(fname, "%s/time_dwudp.dat", nome);
	ft[udpDW] = fopen(fname, "w");
	if (ft[udpDW] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		return INVALID_FOLDER;
	}
	sprintf(fname, "%s/time_uptcp.dat", nome);
	ft[tcpUP] = fopen(fname, "w");
	if (ft[tcpUP] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		fclose(ft[udpDW]);
		return INVALID_FOLDER;
	}
	sprintf(fname, "%s/time_dwtcp.dat", nome);
	ft[tcpDW] = fopen(fname, "w");
	if (ft[tcpDW] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		fclose(ft[udpDW]);
		fclose(ft[tcpUP]);
		return INVALID_FOLDER;
	}
	
	for (i=0; i<FLOWS; i++) {
		print_time_flow(t, i);
		fclose( ft[i] );
	}
	
	return 0;	
}

void print_time_flow(time_stat *t, int flow) {
	time_stat* to_print = t;
	
	while ( to_print != NULL ) {
		if ( to_print->pkt[flow] > 0 ) {
			fprintf(ft[flow], "%lu %ld %d\n", to_print->ts, to_print->size[flow], to_print->pkt[flow]);
		}
		
		to_print = to_print->next;
	}
	
	return;
}

long timeval_difference(struct timeval a, struct timeval b) {
	return ((a.tv_sec - b.tv_sec)*1000000 + a.tv_usec - b.tv_usec)/1000000;
}
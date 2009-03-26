#include <stdio.h>
#include <stdlib.h>
#include "time.h"

FILE* ft[FLOWS];
/**
 * Parse the information of a packet
 */
void register_packet(time_stat *t, packet_stat *pkt, int direction) {
	if ( pkt->timestamp / TIME_GRANULARITY == t->ts ) {
		/* This packet goes here */
		int flow;
		if (direction == upstream) {
			flow = (pkt->proto == IPPROTO_TCP) ? tcpUP : udpUP;
		} else {
		    flow = (pkt->proto == IPPROTO_TCP) ? tcpDW : udpDW;
		}
		
		t->pkt[flow]++;
		t->size[flow] += pkt->iplen;
		if (rate(pkt)) {
			t->videopkt[flow]++;
		    t->videosize[flow] += pkt->iplen;
		}
		
	} else {
		if ( t->last == NULL ) {
			/* I only have one object I need a new structure */
			time_stat* new = (time_stat*) malloc(sizeof(time_stat));
		
			init_time_stat(new);
			new->ts = (int)pkt->timestamp/TIME_GRANULARITY;
		
			// Link it
			t->next = new;
			t->last = new;
		} else if ( (int)pkt->timestamp / TIME_GRANULARITY > t->last->ts ) {
			/* Time is flowing, I need a new structure */
			time_stat* new = (time_stat*) malloc(sizeof(time_stat));
		
			init_time_stat(new);
			new->ts = (int)pkt->timestamp/TIME_GRANULARITY;;
		
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
		timestamp->videopkt[i] = 0;
		timestamp->videosize[i] = 0;
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
	fprintf(ft[udpUP], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB]\n");
	
	sprintf(fname, "%s/time_dwudp.dat", nome);
	ft[udpDW] = fopen(fname, "w");
	if (ft[udpDW] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		return INVALID_FOLDER;
	}
	fprintf(ft[udpDW], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB]\n");
	
	sprintf(fname, "%s/time_uptcp.dat", nome);
	ft[tcpUP] = fopen(fname, "w");
	if (ft[tcpUP] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		fclose(ft[udpDW]);
		return INVALID_FOLDER;
	}
	fprintf(ft[tcpUP], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB]\n");
	
	sprintf(fname, "%s/time_dwtcp.dat", nome);
	ft[tcpDW] = fopen(fname, "w");
	if (ft[tcpDW] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		fclose(ft[udpDW]);
		fclose(ft[tcpUP]);
		return INVALID_FOLDER;
	}
	fprintf(ft[tcpDW], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB]\n");
	
	sprintf(fname, "%s/time_stream.dat", nome);
	ft[udp] = fopen(fname, "w");
	if (ft[udp] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		fclose(ft[udpDW]);
		fclose(ft[tcpUP]);
		fclose(ft[tcpDW]);
		return INVALID_FOLDER;
	}
	fprintf(ft[udp], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB]\n");
	
	for (i=0; i<FLOWS; i++) {
		print_time_flow(t, i);
		fclose( ft[i] );
	}
	
	return 0;	
}

void print_time_flow(time_stat *t, int flow) {
	time_stat* to_print = t;
	/* Add zeros in statistics */
	u_long i=0;
	while ( i <= t->last->ts ) {
		if ( to_print->ts <= i ) {
			fprintf(ft[flow], "%d %ld %d %d %d\n", to_print->ts * TIME_GRANULARITY, to_print->size[flow]/(1024 * TIME_GRANULARITY), to_print->pkt[flow], to_print->videopkt[flow], to_print->videosize[flow]/(1024*TIME_GRANULARITY));
			to_print = to_print->next;
		} else {
			fprintf(ft[flow], "%lu 0 0\n", i);
		}
		
		i++;
	}
	
	return;
}

int timeval_difference(struct timeval a, struct timeval b) {
	return (a.tv_sec - b.tv_sec) + (a.tv_usec - b.tv_usec)/1000000;
}

/* Is a bigger than b ? */
boolean timeval_bigger(struct timeval a, struct timeval b) {
	if ( a.tv_sec == b.tv_sec ) {
		return (a.tv_usec > b.tv_usec) ? true : false;
	}
	
	return (a.tv_sec > b.tv_sec) ? true : false;
}

/* This function has to decide if the considered packet is a video packet or not
 * It returns a boolean value:
 *   - TRUE : video (or eventually data)
 *   - FALSE : other type
 */

boolean rate(packet_stat *pkt){
	//printf("%x %x %x %d \n", pkt->id_peer,pkt->type[0], pkt->type_flag[0], pkt->length[0] );
	if ( (pkt->type[0] == 6) && (pkt->type_flag[0] == 1) && (pkt->length[0] > 1000) && (pkt->segments == 1) )
	  return true;
	return false;	  
}

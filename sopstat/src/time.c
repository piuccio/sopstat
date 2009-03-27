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
		u_long host;
		int flow;
		
		/* Add the hostname */
		host = (direction == upstream) ? pkt->dst : pkt->src;
		
		if ( pkt->proto == IPPROTO_TCP ) {
			flow = (direction == upstream) ? tcpUP : tcpDW;
		} else {
			flow = (direction == upstream) ? udpUP : udpDW;
			/* It goes also in the aggregated udp flow */
			t->pkt[udp]++;
			t->size[udp] += pkt->iplen;
			if (is_video(pkt)) {
				t->videopkt[udp]++;
		    	t->videosize[udp] += pkt->iplen;
			}
			if (is_discovery(pkt)){
				t->discoverypkt[udp]++;
				t->discoverysize[udp]+=pkt->iplen;
			}
			register_host(host, t, udp);
		}
		
		t->pkt[flow]++;
		t->size[flow] += pkt->iplen;
		if (is_video(pkt)) {
			t->videopkt[flow]++;
		    t->videosize[flow] += pkt->iplen;
		}
		if (is_discovery(pkt)){
				t->discoverypkt[flow]++;
				t->discoverysize[flow]+=pkt->iplen;
			}
		register_host(host, t, flow);
		
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
		timestamp->hosts[i] = 0;
		timestamp->pkt[i] = 0;
		timestamp->size[i] = 0;
		timestamp->videopkt[i] = 0;
		timestamp->videosize[i] = 0;
		timestamp->hostnames[i] = NULL;
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
	fprintf(ft[udpUP], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB] [Number of host] [discovery pkt] [discovery rate Bps]\n");
	
	sprintf(fname, "%s/time_dwudp.dat", nome);
	ft[udpDW] = fopen(fname, "w");
	if (ft[udpDW] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		return INVALID_FOLDER;
	}
	fprintf(ft[udpDW], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB] [Number of host] [discovery pkt] [discovery rate Bps]\n");
	
	sprintf(fname, "%s/time_uptcp.dat", nome);
	ft[tcpUP] = fopen(fname, "w");
	if (ft[tcpUP] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		fclose(ft[udpDW]);
		return INVALID_FOLDER;
	}
	fprintf(ft[tcpUP], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB] [Number of host]\n");
	
	sprintf(fname, "%s/time_dwtcp.dat", nome);
	ft[tcpDW] = fopen(fname, "w");
	if (ft[tcpDW] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		fclose(ft[udpDW]);
		fclose(ft[tcpUP]);
		return INVALID_FOLDER;
	}
	fprintf(ft[tcpDW], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB] [Number of host]\n");
	
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
	fprintf(ft[udp], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB] [Number of host]\n");
	
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
			fprintf(ft[flow], "%d %ld %d %d %d %d %d %d\n", to_print->ts * TIME_GRANULARITY, to_print->size[flow]/(1024 * TIME_GRANULARITY), to_print->pkt[flow], to_print->videopkt[flow], to_print->videosize[flow]/(1024*TIME_GRANULARITY), to_print->hosts[flow], to_print->discoverypkt[flow], to_print->discoverysize[flow]/TIME_GRANULARITY);
			to_print = to_print->next;
		} else {
			fprintf(ft[flow], "%lu 0 0 0 0 0\n", i*10);
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
boolean is_video(packet_stat *pkt){
	if ( (pkt->type[0] == 6) && (pkt->type_flag[0] == 1) && (pkt->length[0] > 1000) && (pkt->segments == 1) )
	  return true;
	return false;	  
}

/* This function has to decide if the considered packet is a discovery packet or not
 * It returns a boolean value:
 *   - TRUE : discovery
 *   - FALSE : other type
 */
boolean is_discovery(packet_stat *pkt){
	if ( (pkt->flag == 0xff) && (pkt->id_peer == 0xff) && (pkt->length[0] == 44 ) && (pkt->segments == 1) )
	  return true;
	return false;	  
}

void register_host(u_long ip, time_stat *t, int flow) {
	ip_host* list = t->hostnames[flow];
	while ( list != NULL ) {
		if ( list->ip == ip ) {
			/* Already in the list */
			list->count++;
			return;
		}
		list = list->next;
	}
	/* If I get here i'm a new host */
	ip_host* new = (ip_host*) malloc(sizeof(ip_host));
	new->ip = ip;
	new->count = 1;
	new->next = t->hostnames[flow];
	t->hostnames[flow] = new;
	t->hosts[flow]++;
}
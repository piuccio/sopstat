#include <stdio.h>
#include <stdlib.h>
#include "time.h"

FILE* ft[FLOWS];
FILE* avg;
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
			t->size[udp] += pkt->iplen - SIZE_UDP;
			
			/* Classify video */
			boolean is_video_pkt = is_video(pkt); 
			if ( is_video_pkt ) {
				t->videopkt[udp]++;
		    	t->videosize[udp] += pkt->iplen - SIZE_UDP - 16; //Remove known bytes
			}
			
			/* Classify discovery */
			boolean is_discovery_pkt = is_discovery(pkt); 
			if ( is_discovery_pkt ){
				t->discoverypkt[udp]++;
				t->discoverysize[udp] += pkt->iplen - SIZE_UDP;
			}
			register_host(host, t, udp, is_video_pkt, is_discovery_pkt);
		}
		
		t->pkt[flow]++;
		t->size[flow] += pkt->iplen - SIZE_UDP;
		boolean is_video_pkt = is_video(pkt); 
		if (is_video_pkt) {
			t->videopkt[flow]++;
		    t->videosize[flow] += pkt->iplen - SIZE_UDP - 16;
		}
		boolean is_discovery_pkt = is_discovery(pkt);
		if (is_discovery(pkt)){
				t->discoverypkt[flow]++;
				t->discoverysize[flow]+=pkt->iplen - SIZE_UDP;
			}
		register_host(host, t, flow, is_video_pkt, is_discovery_pkt);
		
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
		timestamp->discoverypkt[i] = 0;
		timestamp->discoverysize[i] = 0;
		timestamp->video_hosts[i] = 0;
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
	fprintf(ft[udpUP], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB] [Number of host] [discovery pkt] [discovery rate Bps] [Peers]\n");
	
	sprintf(fname, "%s/time_dwudp.dat", nome);
	ft[udpDW] = fopen(fname, "w");
	if (ft[udpDW] == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(ft[udpUP]);
		return INVALID_FOLDER;
	}
	fprintf(ft[udpDW], "#[timesample] [size in kB] [number of packets] [# video packets] [Videosize in kB] [Number of host] [discovery pkt] [discovery rate Bps] [Peers]\n");
	
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
	
	
	sprintf(fname, "%s/averages.dat", nome);
	avg = fopen(fname, "w");
	if (avg == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		return INVALID_FOLDER;
	}
	double avg_video_dw = avg_video_size(t, udpDW);
	double avg_data_on_video_dw = avg_data_on_video_size(t, udpDW);
	double avg_video_up = avg_video_size(t, udpUP);
	double avg_data_on_video_up = avg_data_on_video_size(t, udpUP);
	fprintf(avg, "Total data downloaded %.2f kB\n\n", total_data_size(t, udpDW) );
	fprintf(avg, "Total video downloaded %.2f kB\n\n", total_video_size(t, udpDW) );
	fprintf(avg, "Average data downloaded %.2f kBps\n\n", avg_data_size(t, udpDW) );
	fprintf(avg, "Average video downloaded %.2f kBps \n", avg_video_dw );
	fprintf(avg, "\tover an average data downloaded %.2f kBps", avg_data_on_video_dw );
	fprintf(avg, "\n\t%.2f %%\n\n", avg_video_dw/avg_data_on_video_dw*100.0 );
	fprintf(avg, "Total data uploaded %.2f kB\n\n", total_data_size(t, udpUP) );
	fprintf(avg, "Total video uploaded %.2f kB\n\n", total_video_size(t, udpUP) );
	fprintf(avg, "Average data uploaded %.2f kBps\n\n", avg_data_size(t, udpUP) );
	fprintf(avg, "Average video uploaded %.2f kBps \n", avg_video_up );
	fprintf(avg, "\tover an average data uploaded %.2f kBps", avg_data_on_video_up );
	fprintf(avg, "\n\t%.2f %%\n\n", avg_video_up/avg_data_on_video_up*100.0 );
	
	
	fclose(avg);
	return 0;	
}

void print_time_flow(time_stat *t, int flow) {
	time_stat* to_print = t;
	/* Add zeros in statistics */
	u_long i=0;
	while ( i <= t->last->ts ) {
		if ( to_print->ts <= i ) {
			fprintf(ft[flow], "%d %ld %d %d %d %d %d %d %d\n", to_print->ts * TIME_GRANULARITY, to_print->size[flow]/(1024 * TIME_GRANULARITY), to_print->pkt[flow], to_print->videopkt[flow], to_print->videosize[flow]/(1024*TIME_GRANULARITY), to_print->hosts[flow], to_print->discoverypkt[flow], to_print->discoverysize[flow]/TIME_GRANULARITY, to_print->video_hosts[flow]);
			to_print = to_print->next;
		} else {
			fprintf(ft[flow], "%lu 0 0 0 0 0 0 0 0\n", i*10);
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
	if ( pkt->video_segment >= 0 && pkt->length[pkt->video_segment] > 600 && pkt->sequence[pkt->video_segment] > 1 )
	  return true;
	return false;	  
}

/* This function has to decide if the considered packet is a discovery packet or not
 * It returns a boolean value:
 *   - TRUE : discovery
 *   - FALSE : other type
 */
boolean is_discovery(packet_stat *pkt){
	//if ( (pkt->flag == 0xff) && (pkt->id_peer == 0xff) && (pkt->length[0] == 44 ) && (pkt->segments == 1) )
	if ( (pkt->flag == 0xff) && (pkt->id_peer == 0xff) )
	  return true;
	return false;	  
}

void register_host(u_long ip, time_stat *t, int flow, boolean is_video, boolean is_discovery) {
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
	if (is_video) t->video_hosts[flow]++;
	if (is_discovery) t->discoveryhosts[flow]++;
}

/*
 * This function is used to automatically print all the pictures related to the analyzed capture
 */
void print_graph(char* base_name, char * dir_name){
	FILE* parameters;
	
	char fname[FILENAME_MAX];
	sprintf(fname, "%s/parameters.gp", base_name);
	parameters = fopen(fname, "w");
	if (parameters == NULL) {
		printf("[ERROR] Unable to create %s\n", fname);
		fclose(parameters);
		return;
	}
	fprintf(parameters, "#File with gnuplot parameters\n");
	fprintf(parameters, "set macros\n");
	fprintf(parameters, "name = \"%s\"\n", dir_name);
	fprintf(parameters, "dir = \"%s\"\n", base_name);
	fprintf(parameters, "`if [ ! -d @dir/@name ]; then mkdir @dir/@name ;  fi`\n");
	//fprintf(parameters, "load sprintf(\"%s/print.plt\",dir)");
	fprintf(parameters, "load sprintf(\"%s/print.plt\",dir)","%s");
	fclose(parameters);
	char command[FILENAME_MAX];
	sprintf(command, "gnuplot %s", fname);
	if (system(command)) printf("[ERROR] Something wrong with %s", command);
}

double avg_video_size(time_stat *time, int flow) {
	time_stat* t = time;
	int num_samples=0,total_size=0;
	
	while (t != NULL) {
		if ( t->videopkt[flow] > 0 ) {
			num_samples++;
			total_size += t->videosize[flow];
		}
		t = t->next;
	}
	
	return (total_size/1024.0)/(num_samples*TIME_GRANULARITY);
}

double avg_data_size(time_stat *time, int flow) {
	time_stat* t = time;
	int num_samples=0,total_size=0;
	
	while (t != NULL) {
		if ( t->pkt[flow] > 0 ) {
			num_samples++;
			total_size += t->size[flow];
		}
		t = t->next;
	}
	
	return (total_size/1024.0)/(num_samples*TIME_GRANULARITY);
}

double avg_data_on_video_size(time_stat *time, int flow) {
	time_stat* t = time;
	int num_samples=0,total_size=0;
	
	while (t != NULL) {
		if ( t->videopkt[flow] > 0 ) {
			num_samples++;
			total_size += t->size[flow];
		}
		t = t->next;
	}
	
	return (total_size/1024.0)/(num_samples*TIME_GRANULARITY);
}

double total_data_size(time_stat *time, int flow) {
	time_stat* t = time;
	int total_size=0;
	
	while (t != NULL) {
		total_size += t->size[flow];
		t = t->next;
	}
	
	return total_size/1024.0;
}

double total_video_size(time_stat *time, int flow) {
	time_stat* t = time;
	int total_size=0;
	
	while (t != NULL) {
		total_size += t->videosize[flow];
		t = t->next;
	}
	
	return total_size/1024.0;
}
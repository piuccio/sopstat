/**
 * Build some statistics for the sopcast payload
 */

#include <stdio.h>
#include <stdlib.h>
#include "payload.h"

void add_payload_stat(payload_stat *s, u_short val) {
	if (s->value == val) {
		/* Here, update */
		s->num++;
	} else if ( s->next == NULL ) {
		/* I need a new one */
		payload_stat* new = (payload_stat*) malloc(sizeof(payload_stat));
		
		/* Fill */
		new->value = val;
		new->num = 1;
		new->next = NULL;
		
		/* Link */
		s->next = new;
	} else {
		add_payload_stat(s->next, val);
	}
}

void print_payload_statistics(payload_stat_container* container, FILE* f) {
	fprintf(f,"#[value] [count]\n");
	fprintf(f,"#FLAG\n");
	print_payload_stat(container->flag, f);
	fprintf(f,"#ID_PEER\n");
	print_payload_stat(container->id_peer, f);
	fprintf(f,"#SEGMENTS\n");
	print_payload_stat(container->segments, f);
	fprintf(f,"#ID_STREAM\n");
	print_payload_stat(container->id_stream, f);
	fprintf(f,"#TYPE\n");
	print_payload_stat(container->type, f);
	fprintf(f,"#TYPE_FLAG\n");
	print_payload_stat(container->type_flag, f);
	fprintf(f,"#LENGTH\n");
	print_payload_stat(container->length, f);
	
}

void print_payload_stat(payload_stat* s, FILE* f) {
	if (s != NULL) {
		fprintf(f, "%.2hx %d\n", s->value, s->num);
		print_payload_stat(s->next, f);
	} 
}

void print_video_payload(ipnode* n, FILE* f) {
	packet_stat *s;
	int i,j,maxi,maxp;
	/* Iterate on the node */
	while (n != NULL) {
		/* Get the first stat and iterate */
		s = n->first[udpDW];
		while (s != NULL) {
			/* How many segments ? */
			maxi = s->segments > MAX_SEGMENTS ? MAX_SEGMENTS : s->segments;
			for (i=0; i<maxi; i++) {
				/* Only the video part */
				if ( s->type[i] == 6 && s->type_flag[i] == 1) {
					/* How many bytes */
					maxp = s->length[i] > MAX_PAYLOAD ? MAX_PAYLOAD : s->length[i];
					for (j=0; j<maxp; j++) {
						fprintf(f,"%.2x ", s->payload[i][j]);
					}
				}
			}
			/* Next stat for this node */
			s = s->next;
			fprintf(f,"\n");
		}
		/* Next node */
		n = n->next;
		fprintf(f,"#\n");
	}
}

void print_video(video_flow *video, FILE *f) {
	video_list* data = video->data;
	int i;
	while (data != NULL) {
		//fprintf(f,"[%ld.%ld]seq %d\n", data->ts.tv_sec, data->ts.tv_usec, data->sequence);
		fprintf(f,"[%.3d] ", data->sequence);
		for (i=0; i<data->length_stored; i++) {
			fprintf(f,"%.2x ", data->payload[i]);
		}
		fprintf(f,"\n");
		data = data->next;
	}
	printf("Total of %d out of sequence packets", video->out_of_sequence);
}

void exctract_video(video_flow* video, packet_stat* stat, u_int host) {
	/* Is this a video packet ? */
	if ( stat->video_segment < 0 ) return;

	/* Is there something in the list */
	if (video->host == NULL) {
		// First packet
		host_pointer* h = (host_pointer*)malloc(sizeof(host_pointer));
		// Store the ip
		h->ip = host;
		// create a new data info
		video_list* data = (video_list*)malloc(sizeof(video_list));
		fill_video(data, stat);
		// store it
		h->last = data;
		video->data = data;
		video->last = data;
		video->host = h;
	} else {
		/* Find the pointer to the last packet for that host */
		host_pointer* h = video->host;
		while( h != NULL ) {
			if ( h->ip == host ) {
				/* Host is here, check for retransmission */
				if ( h->last->sequence >= stat->sequence[stat->video_segment] ) {
					//Out of sequence
					printf("[%ld.%ld]Out of sequence %d after %d\n", stat->real_ts.tv_sec, stat->real_ts.tv_usec, stat->sequence[stat->video_segment], h->last->sequence);
					video->out_of_sequence++;
				} else {
					//Valid
					video_list* data = (video_list*)malloc(sizeof(video_list));
					fill_video(data, stat);
					//Store it in the very last position for the host and the video
					video->last->next = data;
					h->last = data;
					video->last = data;
				}
				// Video stored, return
				return;
			}
			/* Next host */
			h = h->next;
		}
		
		/* This is a new host!! */
		host_pointer* new_h = (host_pointer*)malloc(sizeof(host_pointer));
		new_h->ip = host;
		// create a new data info
		video_list* data = (video_list*)malloc(sizeof(video_list));
		fill_video(data, stat);
		// store the host, new host in front
		new_h->last = data;
		new_h->next = video->host;
		video->host = new_h;
		// and also the data
		video->last->next = data;
		video->last = data;
	}
}

void fill_video(video_list* data, packet_stat* stat) {
	int i;
	data->length_stored = (stat->length[stat->video_segment] > MAX_PAYLOAD) ? MAX_PAYLOAD : stat->length[stat->video_segment];
	data->sequence = stat->sequence[stat->video_segment];
	data->ts = stat->real_ts;
	for (i=0; i<data->length_stored; i++) {
		data->payload[i] = stat->payload[stat->video_segment][i];
	}
	data->next = NULL;
}
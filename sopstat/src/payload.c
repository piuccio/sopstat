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
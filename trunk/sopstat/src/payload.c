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
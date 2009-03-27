#ifndef PAYLOAD_H_
#define PAYLOAD_H_

#include "constants.h"
#include "liste.h"

/*
typedef struct payload_stat {
	u_short value;
	int num;
	struct payload_stat* next;
} payload_stat;

typedef struct payload_stat_container {
	payload_stat* flag;
	payload_stat* id_peer;
	payload_stat* segments;
	payload_stat* id_stream;
	payload_stat* type;
	payload_stat* type_flag;
	payload_stat* length;
} payload_stat_container;
*/

/* Prototypes */
void add_payload_stat(payload_stat *, u_short);
void print_payload_statistics(payload_stat_container* , FILE* );
void print_payload_stat(payload_stat* , FILE* );
void print_video_payload(ipnode* n, FILE* f);

#endif /*PAYLOAD_H_*/

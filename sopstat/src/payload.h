#ifndef PAYLOAD_H_
#define PAYLOAD_H_

#include"constants.h"

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

typedef struct chisquare {
	double x;
	int num[CHISQUARE_INTERVALS];
	int total_num;
} chisquare;

/* Prototypes */
void add_payload_stat(payload_stat *, u_short);
void print_payload_statistics(payload_stat_container* , FILE* );
void print_payload_stat(payload_stat* , FILE* );
	
#endif /*PAYLOAD_H_*/

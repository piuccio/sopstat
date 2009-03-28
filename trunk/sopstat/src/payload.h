#ifndef PAYLOAD_H_
#define PAYLOAD_H_

#include "constants.h"
#include "liste.h"

typedef struct video_flow {
	int out_of_sequence; /* Count the number of out of sequence */
	struct host_pointer* host; /* List of the host pointers */
	struct video_list* data; /* List of the ordered packets */
	struct video_list* last; /* Last packet in the list */
} video_flow;

typedef struct host_pointer {
	u_int ip;
	struct video_list* last;
	struct host_pointer* next;
} host_pointer;

typedef struct video_list {
	u_short payload[MAX_PAYLOAD];
	struct timeval ts;
	int sequence;
	int length_stored;
	int retransmission;
	struct video_list* next;
} video_list;
	

/* Prototypes */
void add_payload_stat(payload_stat *, u_short);
void print_payload_statistics(payload_stat_container* , FILE* );
void print_payload_stat(payload_stat* , FILE* );
void print_video_payload(ipnode*, FILE* );
void print_video(video_flow*, FILE*);
void exctract_video(video_flow*, packet_stat*, u_int);
void fill_video(video_list*, packet_stat*);

#endif /*PAYLOAD_H_*/

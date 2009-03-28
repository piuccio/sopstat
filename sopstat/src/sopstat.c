/***************************************************************************
 *   Copyright (C) 2009 by Fabio Crisci                                    *
 *   fabio.crisci@gmail.com                                                *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
/** 
 * Parses an input file with the captured sopcast stream creating output
 * statistics files
 **/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include "constants.h"
#include "packet.h"
#include "liste.h"
#include "time.h"
#include "payload.h"

/* Prototypes */
void usage(void);
void populate_tree(u_char *, const struct pcap_pkthdr *, const u_char *);

u_int local_ip; /* hexadecimal form, should be easier to compare */
struct bpf_program fp;		/* The compiled filter expression */
char filter_exp[] = "not(udp.port < 1028) and not(udp.port == 42166)";

/* List of packets */
ipnode* tree;
long num_pkt=0;
FILE* payload;
payload_stat_container* container;
int i;
video_flow* video;

/* Time dimension */
time_stat* timestamp; 

int main(int argc, char* argv[]) {
		 
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        
        /* Check required inputs */
        if ( argc < 4 ) {
                usage();
                return INPUT_ERROR;
        }

        /* Try top open the file with the pcap lybraries */
        handle = pcap_open_offline(argv[1], errbuf);
        if (handle == NULL) {
                printf("[ERROR] Unable to open %s\n\t%s \n", argv[1], errbuf);
                return INPUT_ERROR;
        }
        /* Filters out unwanted traffic
        if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
			printf("[ERROR] Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return FILTER_ERROR;
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			printf("[ERROR] Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return FILTER_ERROR;
		}
        */
        
        /* Take the local IP */
        if ( stoip(&local_ip, argv[3]) == false ) {
        	//Unable to convert the IP, this is not valid
        	printf("[ERROR] Invalid local IP address %s\n", argv[3]);
        	return INVALID_IP;
        }
        
        /* Initialize the tree */
        tree = (ipnode*) malloc (sizeof(ipnode));
        if (tree == NULL) {
        	printf("[ERROR] Unable to allocate memory for the tree");
        	return MALLOC_ERROR;
        } else {
			tree->next=NULL;
			tree->ip=0;
			for (i=0; i<FLOWS; i++) {
				tree->first[i] = NULL;
				tree->last[i] = NULL;
			}
        }
        /* Initialize the time */
        timestamp = (time_stat*) malloc (sizeof(time_stat));
        if (timestamp == NULL ) {
        	printf("[ERROR] Unable to allocate memory for the timestamp");
        	return MALLOC_ERROR;
        }
        init_time_stat(timestamp);
        
		/* Open the file for the payload */
		char fname[FILENAME_MAX];
		sprintf(fname, "%s/payload.dump", argv[2]);
		payload = fopen(fname, "w");
		if (payload == NULL) {
			printf("[ERROR] Unable to create %s\n", fname);
			return INVALID_FOLDER;
		} else {
			container = (payload_stat_container*) malloc(sizeof(payload_stat_container));
			container->flag = NULL;
			container->id_peer = NULL;
			container->segments = NULL;
			container->id_stream = NULL;
			container->type = NULL;
			container->type_flag = NULL;
			container->length = NULL;
		}
		/* Init the video structure */
		video = (video_flow*)malloc(sizeof(video_flow));
		video->out_of_sequence = 0;
		video->host = NULL;
		video->data = NULL;
		video->last = NULL;
        
        /* Grab packet in a loop */
		printf("Processing file %s, this may take a while\n", argv[1]); 
        pcap_loop(handle, -1, populate_tree, NULL);
		
		/* And close the session */
        pcap_close(handle);
	
		/* Print the tree */
		if ( print(tree, argv[2]) != NO_ERROR ) {
			return INVALID_FOLDER;
		}
		
		/* Print the time */
		if ( print_time(timestamp, argv[2]) != NO_ERROR ) {
			return INVALID_FOLDER;
		}
		
		/* Dump the payload */ 
		//dump_udp_payload(tree, payload);
		//print_payload_statistics(container, payload);
		//print_chisquare(tree, payload);
		//print_video_payload(tree, payload);
		print_video(video, payload);
		
		printf("\nOperation completed successfully\n");
		printf("%ld packet analyzed in %f seconds\n", num_pkt, (float)clock()/CLOCKS_PER_SEC);
		fclose(payload);
        return NO_ERROR; 
}

void usage(void) {
        printf("Sopstat is a postprocessing tools for the analisys of a pcap capture of the sopcast traffic\n");
        printf("USAGE:\n\t sopstat capture.pcap path_to_results ip_address\n");
        printf("\t- capture.pcap is a pcap capture containing the stream to analyze, ");
        printf("analysis must be filtered such that each packet involve one single host.\n");
        printf("\t- path_to_results is the folder where sopstat will generate the files containing the statistics\n");
        printf("\t- ip_address is the host that is generating or receiving the sopcast stream\n");
        printf("\t- [ip_address] isolate a flow and dump the udp payload\n");
        printf("This software will output the statistics in the specified folder\n");
}

void populate_tree(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* Structure for the relevant informations */
	struct packet_stat stat;
	

	if ( !parse_packet(&stat, header, packet, container ) ) {
		//Nothing to do for this packet
		#ifdef DEBUG
			printf("\nDropping a packet at time %ld\n", stat.timestamp);
		#endif
		return;
	}
	
	/* Output something to show that the program is not crashed :P */
	num_pkt++;
	if (num_pkt % 1000 == 0) {
		if (num_pkt % 100000 == 0) {
			printf("+\n");
			fflush(stdout);
		} else {
			printf(".");
			fflush(stdout);
		}
	}
	
	/* This is a valid packet, store it in the packet tree */
	//The host node must be different from local_ip
	u_int host;
	host = (stat.src == local_ip) ? stat.dst : stat.src;
	direction dir = (stat.src == local_ip) ? upstream : downstream;
	insert_node(tree, host, &stat, dir);
	/* Compute the chi square test */
	update_global_chisquare(tree, &stat, dir);
	
	/* Store it also in the time dimension */
	register_packet(timestamp, &stat, dir);
	
	/* Extract the video information */
	exctract_video(video, &stat, host);
}



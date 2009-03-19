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

/* Prototypes */
void usage(void);
void populate_tree(u_char *, const struct pcap_pkthdr *, const u_char *);

//FILE* f[MAX_OPEN_FILES];
//char fname[FILENAME_MAX];
u_int local_ip; /* hexadecimal form, should be easier to compare */

/* List of packets */
ipnode* tree;
long num_pkt=0;
int i;

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
        
        /* Take the local IP */
        if ( stoip(&local_ip, argv[3]) == false ) {
        	//Unable to convert the IP, this is not valid
        	printf("[ERROR] Invalid IP address %s\n", argv[3]);
        	return INVALID_IP;
        }
        #ifdef DEBUG
        	printf("Local IP address: %#x\n", local_ip);
        #endif
        
        /* Initialize the tree */
        tree = (ipnode*) malloc (sizeof(ipnode));
        if (tree == NULL) {
        	printf("[ERROR] Unable to allocate memory for the tree");
        	return MALLOC_ERROR;
        } else {
			tree->next=NULL;
			tree->ip=0;
			for (i=0; i<4; i++) {
				tree->first[i] = NULL;
				tree->last[i] = NULL;
			}
        }
        
        /* Grab packet in a loop */
		printf("Processing file %s, this may take a while\n", argv[1]); 
		
		/* Check if there is the 4th parameter that changes the time granularity */
        if ( false ) {
        	u_char aux [] = "pippo";
        	pcap_loop(handle, -1, populate_tree, aux);
        } else {
        	pcap_loop(handle, -1, populate_tree, NULL);
        }
		
		/* And close the session */
        pcap_close(handle);
	
		/* Print the tree */
		if ( print(tree, argv[2]) != 0) {
			return INVALID_FOLDER;
		}
		
		printf("\nOperation completed successfully\n");
		printf("%ld packet analyzed in %f seconds\n", num_pkt, (float)clock()/CLOCKS_PER_SEC);
        return NO_ERROR; 
}

void usage(void) {
        printf("Sopstat is a postprocessing tools for the analisys of a pcap capture of the sopcast traffic\n");
        printf("USAGE:\n\t sopstat capture.pcap path_to_results ip_address\n");
        printf("\t- capture.pcap is a pcap capture containing the stream to analyze, ");
        printf("analysis must be filtered such that each packet involve one single host.\n");
        printf("\t- path_to_results is the folder where sopstat will generate the files containing the statistics\n");
        printf("\t- ip_address is the host that is generating or receiving the sopcast stream\n");
        printf("This software will output the statistics in the specified folder\n");
}

void populate_tree(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* Structure for the relevant informations */
	struct packet_stat stat;
	

	if ( !parse_packet(&stat, header, packet) ) {
		//Nothing to do for this packet
		#ifdef DEBUG
			printf("\nDropping a packet at time %ld\n", stat.timestamp);
		#endif
		return;
	}
	
	/* Output something to show that the program is not crashed :P */
	num_pkt++;
	if (num_pkt % 1000 == 0) {
		printf(".");
		fflush(stdout);
	}
	
	/* This is a valid packet, store it in the tree */
	//The host node must be different from local_ip
	u_int host;
	host = (stat.src == local_ip) ? stat.dst : stat.src;
	direction dir = (stat.src == local_ip) ? upstream : downstream;
	insert_node(tree, host, &stat, dir);
}


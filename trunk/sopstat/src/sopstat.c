/** Sopstat
 * This is the main file, it parses an input file
 * with the captured stream creating an output file
 * with some statistics
 **/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "constants.h"
#include "packet.h"

void usage(void);
void populate_tree(u_char *, const struct pcap_pkthdr *, const u_char *);

FILE* f[MAX_OPEN_FILES];
char fname[FILENAME_MAX];

/* List of packets */
struct host *pkt_tree;
long num_pkt=0;

int main(int argc, char* argv[]) {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];

        // The input file is required
        if ( argc < 3 ) {
                usage();
                return INPUT_ERROR;
        }

        /* Try top open the file with the pcap lybraries */
        handle = pcap_open_offline(argv[1], errbuf);
        if (handle == NULL) {
                printf("[ERROR] Unable to open %s\n\t%s \n", argv[1], errbuf);
                return INPUT_ERROR;
        }
        
        /* Try to access the output path */
        //packet level statistics
        sprintf(fname, "%s/distribution_tcp.dat", argv[2]);
        f[PKT_DISTR_TCP] = fopen(fname, "w");
        if (f[PKT_DISTR_TCP] == NULL) {
        	printf("[ERROR] Unable to create %s\n", fname);
			return INPUT_ERROR;
        }
        //time level statistics
        sprintf(fname, "%s/distribution_udp.dat", argv[2]);
        f[PKT_DISTR_UDP] = fopen(fname, "w");
        if (f[PKT_DISTR_UDP] == NULL) {
        	printf("[ERROR] Unable to create %s\n", fname);
        	fclose(f[PKT_DISTR_TCP]);
			return INPUT_ERROR;
        }

        /* Grab packet in a loop */
        printf("Processing file %s, this may take a while\n", argv[1]); 
        pcap_loop(handle, -1, populate_tree, NULL);

        /* And close the session */
        pcap_close(handle);
        fclose(f[PKT_DISTR_TCP]);
        fclose(f[PKT_DISTR_UDP]);

		printf("\nOperation completed successfully\n");
		printf("%ld packet analyzed\n", num_pkt);
        return NO_ERROR; 
}

void usage(void) {
        printf("Sopstat is a postprocessing tools for the analisys of a pcap capture of the sopcast traffic\n");
        printf("USAGE:\n\t sopstat capture.pcap path_to_results\n");
        printf("This software will output the statistics in the specified folder\n");
}

void populate_tree(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* Structure for the relevant informations */
	struct packet_stat stat;
	
	/* Create the statistics for this file */
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
	}
	
	/* This is a valid packet store it in the tree */
	
	
	/* And output to file */
	char serial[MAX_SERIALIZATION];
	serialize_packet( &stat, serial );
	/* Write in the packet level stats according to the type */
	switch( stat.proto ) {
        case IPPROTO_TCP:
			fprintf(f[PKT_DISTR_TCP], "%s\n", serial);
			break;
		case IPPROTO_UDP:
			fprintf(f[PKT_DISTR_UDP], "%s\n", serial);
			break;
		default:
			printf("\nError in protocol representation\n");
			break;
	}
}



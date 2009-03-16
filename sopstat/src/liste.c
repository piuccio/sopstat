/* In this library we are going to define the type of the structure that
 * we will intend to use */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "packet.h"
#include "liste.h"

/**
 * Insert a statistic packet inside a list
 */
void insert_stat(statnode *n , node pkt ) {
		if (n->next_stat != NULL) {
			insert_stat(n->next_stat, pkt);
		} else {
			statnode* last = (statnode*) malloc (sizeof(statnode));
			strcpy(last->par1, pkt.par1);
			printf("Inserita statistica: %s\n", last->par1);
			last->next_stat = NULL;
			n->next_stat = last;
		}
		return;
}

/**
 * Insert a new node inside the structure
 * 
 * First look if the ip already exists, otherwise it creates a new one
 * and insert the passed node, containing the collected statistics  
 */
void insert_node(ipnode* n, node pkt){
	if (strcmp(n->address,pkt.ipadd)==0){
		/* Node existing */
		printf("EntraTO.. trovato ind uguale\n");
		insert_stat(n->first_stat, pkt);
	} else if (n->next_ip != NULL){
		/* Iterate on next host. Recursive call */
		insert_node(n->next_ip, pkt);
  	} else {
		/* Create a new ip node */
		ipnode* last = (ipnode*) malloc (sizeof(ipnode));
		strcpy(last->address, pkt.ipadd);
		last->next_ip = NULL;
		last->first_stat = (statnode*) malloc (sizeof(statnode));
		strcpy(last->first_stat->par1, pkt.par1);
		printf("Inserita statistica: %s\n", last->first_stat->par1);
		last->first_stat->next_stat = NULL;
		n->next_ip = last;  
	}
	return;
}

void print(ipnode* n){
	if (n != NULL){
	printf("\n -%s- \n", n->address);
	statnode * tmp = n->first_stat;
	while (tmp != NULL) {
	   printf(" %s -> ", tmp->par1);
	   tmp = tmp->next_stat;
	}
	if (n->next_ip != NULL);
		print(n->next_ip);
	}
	printf("\n");
	return;
}
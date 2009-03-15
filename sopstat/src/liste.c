/* In this library we are going to define the type of the structure that
 * we will intend to use */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "packet.h"
#include "liste.h"


void insert_stat(statnode *n , node test ) {
		if (n->next_stat != NULL) {
			insert_stat(n->next_stat, test);
		} else {
			statnode* last = (statnode*) malloc (sizeof(statnode));
			strcpy(last->par1, test.par1);
			printf("Inserita statistica: %s\n", last->par1);
			last->next_stat = NULL;
			n->next_stat = last;
		}
		return;
}

/* Function that has to insert a new node inside the structure. First look if the ip
 * already exists, otherwise it creates a new one and insert the passed node, containing the
 * collected statistics  */
 
void insert_node(ipnode* n, node test){
  // The node containing the ip already exists
  //printf("EntraTO.. insert_node\n");
  //fflush(stdout);
  if (strcmp(n->address,test.ipadd)==0){
  	 // Insert the statitistics
  	 printf("EntraTO.. trovato ind uguale\n");
  //fflush(stdout);
  	 insert_stat(n->first_stat, test);
  } else 
  		if (n->next_ip != NULL){
  			  //	 printf("EntraTO.. recursive \n");
  		   insert_node(n->next_ip, test); // Recursive call
  		} else {
  			// create a new ip node
  			//printf("EntraTO crea new ip\n..");
            //fflush(stdout);
  			ipnode* last = (ipnode*) malloc (sizeof(ipnode));
  			strcpy(last->address, test.ipadd);
  			last->next_ip = NULL;
  			last->first_stat = (statnode*) malloc (sizeof(statnode));
  			strcpy(last->first_stat->par1, test.par1);
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

void provalista(void){
 printf("Entrato in liste.c\n");
 
}


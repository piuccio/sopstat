#ifndef LISTE_H_
#define LISTE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "packet.h"


typedef struct node{
	char ipadd [MAX_IP_ADDR];
	char par1 [MAX_IP_ADDR];
} node;

typedef struct statnode {
	char par1 [MAX_IP_ADDR];
	struct statnode* next_stat;	
} statnode;

typedef struct ipnode {
   char  address [MAX_IP_ADDR];
   struct statnode* first_stat;
   struct ipnode* next_ip;    	
} ipnode;

void insert_stat(statnode * , node  );
void insert_node(ipnode* , node);
void print(ipnode* );
void provalista(void);

#endif /*LISTE_H_*/

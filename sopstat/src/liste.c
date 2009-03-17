/***************************************************************************
 *   Copyright (C) 2009 by Matteo Mana                                     *
 *   matteo.mana@gmail.com                                                *
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
 * This file defines the list structure that separates the network
 * flows by hosts 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "packet.h"
#include "liste.h"

/**
 * Insert a statistic packet inside a list
 */
FILE* f[MAX_OPEN_FILES]; 
char ip[MAX_IP_ADDR];
void insert_stat(packet_stat *n, packet_stat *pkt) {
		if (n->next != NULL) {
			insert_stat(n->next, pkt);
		} else {
			//printf("    - New node inserted\n");
			packet_stat* last = (packet_stat*) malloc (sizeof(packet_stat));
			statcopy(last, pkt);
			n->next = last;
		}
		return;
}

/**
 * Insert a new node inside the structure
 * 
 * First look if the ip already exists, otherwise it creates a new one
 * and insert the passed node, containing the collected statistics  
 */
void insert_node(ipnode* n, u_int hostip, packet_stat *pkt, direction dir){
	//printf("check IP: %x contro %x\n",n->ip, hostip);
	if ( n->ip == hostip ){
		/* Node existing */
		//printf("Trovato nodo uguale!!! %x %x", n->ip, hostip);
		if (dir == upstream) 
			if (pkt->proto == IPPROTO_TCP) // Insert in upTCP
			    insert_stat(n->upTCP, pkt);
			else  insert_stat(n->upUDP, pkt);  //Insert in upUDP
		else
		    if (pkt->proto == IPPROTO_TCP) insert_stat(n->dwTCP, pkt); // Insert in dwTCP
			else   insert_stat(n->dwUDP, pkt);//Insert in dwUDP    
		
		//insert_stat(n->first, pkt);
	} else if (n->next != NULL){
		/* Iterate on next host. Recursive call */
		insert_node(n->next, hostip, pkt, dir);
  	} else {
		/* Create a new ip node */
		ipnode* last = (ipnode*) malloc (sizeof(ipnode));
		//printf("   Create new IP node %x %x \n", n->ip, hostip);
		last->ip = hostip;
		last->next = NULL;
		/* Add the packet stat to the first node */
		last->dwTCP = (packet_stat*) malloc (sizeof(packet_stat));
		last->dwUDP = (packet_stat*) malloc (sizeof(packet_stat));
		last->upTCP = (packet_stat*) malloc (sizeof(packet_stat));
		last->upUDP = (packet_stat*) malloc (sizeof(packet_stat));
		n->next = last;  
		// Insert the node in the right place 
		if (dir == upstream) 
			if (pkt->proto == IPPROTO_TCP) // Insert in upTCP
			    insert_stat(last->upTCP, pkt);
			else  insert_stat(last->upUDP, pkt);  //Insert in upUDP
		else
		    if (pkt->proto == IPPROTO_TCP) insert_stat(last->dwTCP, pkt); // Insert in dwTCP
		    	 //printf("\n !!!!!!!!!! Insert dwTCP !!!!!!!!!! \n"); 
			else   insert_stat(last->dwUDP, pkt);//Insert in dwUDP    
		
		/*
		statcopy(last->first, pkt);
		 Link it in the tree */
		
	}
	return;
}

int print(ipnode *n, char * nome){
	
	char fname[FILENAME_MAX];
	 sprintf(fname, "%s/distribution_dwtcp.dat", nome);
        f[PKT_DISTR_dwTCP] = fopen(fname, "w");
        if (f[PKT_DISTR_dwTCP] == NULL) {
        	printf("[ERROR] Unable to create %s\n", fname);
			return INVALID_FOLDER;
        }
        //packet level statistics UDP
        sprintf(fname, "%s/distribution_dwudp.dat", nome);
        f[PKT_DISTR_dwUDP] = fopen(fname, "w");
        if (f[PKT_DISTR_dwUDP] == NULL) {
        	printf("[ERROR] Unable to create %s\n", fname);
        	fclose(f[PKT_DISTR_dwTCP]);
			return INVALID_FOLDER;
        }
        sprintf(fname, "%s/distribution_uptcp.dat", nome);
        f[PKT_DISTR_upTCP] = fopen(fname, "w");
        if (f[PKT_DISTR_upTCP] == NULL) {
        	printf("[ERROR] Unable to create %s\n", fname);
        	fclose(f[PKT_DISTR_upTCP]);
			return INVALID_FOLDER;
        }
        sprintf(fname, "%s/distribution_upudp.dat", nome);
        f[PKT_DISTR_upUDP] = fopen(fname, "w");
        if (f[PKT_DISTR_upUDP] == NULL) {
        	printf("[ERROR] Unable to create %s\n", fname);
        	fclose(f[PKT_DISTR_dwTCP]);
			return INVALID_FOLDER;
        }
	//printf("printdwTCP: \n");
	printdwTCP(n->next);
	//printf("finish");
	//printf("printupTCP: \n");
	printupTCP(n->next);
	//printf("printdwUDP: \n");
	printdwUDP(n->next);
	//printf("printupUDP: \n");
	printupUDP(n->next);
	int fileind;
	for (fileind=0 ; fileind<MAX_OPEN_FILES-1; fileind++)
	  fclose(f[fileind]);
	return 0;	
}

void printdwTCP(ipnode* n){
	char to_print[MAX_SERIALIZATION];
	//char ip[MAX_IP_ADDR];
	if (n != NULL) {
	  iptos(n->ip, ip);
	  //printf("\n#%s\n", ip) ;
	  fprintf(f[PKT_DISTR_dwTCP],"\n#%s\n", ip) ;
	}
	if (n != NULL) {
		packet_stat * tmp = n->dwTCP->next;
		while (tmp != NULL) {
			serialize_packet(tmp, to_print);
			//printf("%s\n",to_print);
			fprintf(f[PKT_DISTR_dwTCP],"%s\n", to_print);
			tmp = tmp->next;
		}
		if (n->next != NULL);
			printdwTCP(n->next);
		}
	return;
}

void printupTCP(ipnode* n){
	char to_print[MAX_SERIALIZATION];
	char ip[MAX_IP_ADDR];
	if (n!=NULL){
	iptos(n->ip, ip);
	fprintf(f[PKT_DISTR_upTCP],"\n#%s\n", ip) ;}
	if (n != NULL) {
		packet_stat * tmp = n->upTCP->next;
		
		while (tmp != NULL) {
			serialize_packet(tmp, to_print);
			fprintf(f[PKT_DISTR_upTCP],"%s\n", to_print);
			tmp = tmp->next;
		}
		if (n->next != NULL);
			printupTCP(n->next);
		}
	return;
}

void printdwUDP(ipnode* n){
	char to_print[MAX_SERIALIZATION];
	char ip[MAX_IP_ADDR];
	if (n!=NULL) {
	iptos(n->ip, ip);
	fprintf(f[PKT_DISTR_dwUDP],"\n#%s\n", ip) ;}
	if (n != NULL) {
		packet_stat * tmp = n->dwUDP->next;
		while (tmp != NULL) {
			serialize_packet(tmp, to_print);
			fprintf(f[PKT_DISTR_dwUDP],"%s\n", to_print);
			//printf("%s\n", to_print);
			tmp = tmp->next;
		}
		if (n->next != NULL);
			printdwUDP(n->next);
		}
	return;
}

void printupUDP(ipnode* n){
	char to_print[MAX_SERIALIZATION];
	char ip[MAX_IP_ADDR];
	if (n!=NULL){
	iptos(n->ip, ip);
	fprintf(f[PKT_DISTR_upUDP],"\n#%s\n", ip) ;}
	if (n != NULL) {
		packet_stat * tmp = n->upUDP->next;
		while (tmp != NULL) {
			serialize_packet(tmp, to_print);
			fprintf(f[PKT_DISTR_upUDP],"%s\n", to_print);
			tmp = tmp->next;
		}
		if (n->next != NULL);
			printupUDP(n->next);
		}
	return;
}
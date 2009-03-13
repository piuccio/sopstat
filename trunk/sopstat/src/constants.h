#ifndef CONSTANTS_H_
#define CONSTANTS_H_

typedef enum {false, true} boolean;
/**
 * EXIT CODES
 **/
 #define NO_ERROR 0
 #define INPUT_ERROR 10 

/**
 * PROTOCOL CODES
 */
 #define SIZE_ETHERNET 14
 #define SIZE_UDP 8
 #define MAX_IP_ADDR 16
 
/**
 * FILES
 */
 #define MAX_OPEN_FILES 3
 #define PKT_DISTR_TCP 0
 #define PKT_DISTR_UDP 1
 #define TIME_STAT 2
 
#endif /*CONSTANTS_H_*/

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

typedef enum {false, true} boolean;
/**
 * EXIT CODES
 **/
 #define NO_ERROR 0
 #define INPUT_ERROR 10
 #define INVALID_FOLDER 11
 #define INVALID_IP 12
 #define MALLOC_ERROR 20
 #define FILTER_ERROR 30

/**
 * PROTOCOL CODES
 */
 #define SIZE_ETHERNET 14
 #define SIZE_UDP 8
 #define MAX_IP_ADDR 16
 
/**
 * Flow names
 */
 #define FLOWS 5
 #define udpUP 0
 #define udpDW 1
 #define tcpUP 2
 #define tcpDW 3
 #define udp 4
 
 
 /**
  * Parameters
  */
 #define TIME_GRANULARITY 5
 #define CHISQUARE_INTERVALS 16
 
/**
 * Sopcast payload
 */
 #define MAX_SEGMENTS 3
 #define MAX_PAYLOAD 50
 
#endif /*CONSTANTS_H_*/

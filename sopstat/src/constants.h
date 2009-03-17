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

/**
 * PROTOCOL CODES
 */
 #define SIZE_ETHERNET 14
 #define SIZE_UDP 8
 #define MAX_IP_ADDR 16
 
/**
 * FILES
 */
 #define MAX_OPEN_FILES 5
 #define PKT_DISTR_dwTCP 0
 #define PKT_DISTR_dwUDP 1
 #define PKT_DISTR_upTCP 2
 #define PKT_DISTR_upUDP 3
 
 #define TIME_STAT 2
 
#endif /*CONSTANTS_H_*/

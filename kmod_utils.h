#include "types.h"

#ifndef KMOD_UTILS_H
#define KMOD_UTILS_H

int open_raw_socket(void);
void close_raw_socket(void);
int open_raw6_socket(void);
void close_raw6_socket(void);
int send_raw_ipv6(const uint8_t *pkt, uint32_t pktlen);
int send_raw_socket(const uint8_t *pkt, uint32_t pktlen);
void delay_packet_send(const unsigned char *data, unsigned int data_len, unsigned int delay_ms);

#endif /* KMOD_UTILS_H */

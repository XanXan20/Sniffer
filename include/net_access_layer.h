#ifndef NET_ACCESS_LAYER_H
#define NET_ACCESS_LAYER_H

#include <stdio.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#endif

struct ethhdr * find_eth_header(unsigned char *buf, long *buf_len, long *buf_offset);

void print_ethhdr(const struct ethhdr *ethh);

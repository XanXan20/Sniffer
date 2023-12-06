#ifndef NETWORK_LAYER_H
#define NETWORK_LAYER_H

#include <stdio.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#endif

struct iphdr * find_ip_header(unsigned char *buf, long *buf_len, long *buf_offset);

void print_iphdr(const struct iphdr *iph);
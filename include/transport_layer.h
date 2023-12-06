#ifndef TRANSPORT_LAYER_H
#define TRANSPORT_LAYER_H

#include <stdio.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>

#endif

struct icmphdr * find_icmp_header(unsigned char *buf, long *buf_len, long *buf_offset);

void print_icmp_header(const struct icmphdr *icmph);

void print_igmp_header();

void print_ipip_header();

struct tcphdr * find_tcp_header(unsigned char *buf, long *buf_len, long *buf_offset);

void print_tcp_header(const struct tcphdr *tcph);

void print_egp();

void print_pup();

struct udphdr * find_udp_header(unsigned char *buf, long *buf_len, long *buf_offset);

void print_udp_header(struct udphdr *udph);

void print_idp();

void print_tp();

void print_dccp();

void print_rsvp();

void print_gre();

void print_esp();

void print_ah();

void print_mtp();

void print_beetph();

void print_encap();

void print_pim();

void print_comp();

void print_sctp();

void print_udplite();

void print_mpls();

void print_ethernet();
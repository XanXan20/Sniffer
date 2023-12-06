#include "include/transport_layer.h"

/*
    функции для заполнения и вывода структур протоколов транспортного уровня
    так же можно в любой момент дописать реализацию для функций-заглушек
*/

// функции принимают пакет и его длину и смещение в виде указателей
// она заполняет структуру заголовка и изменяет длину непрочитанных данных и смещение 
struct icmphdr * find_icmp_header(unsigned char *buf, long *buf_len, long *buf_offset){
    if(*buf_len <= (long)sizeof(struct icmphdr)) {
        printf("ICMP DATA NONEXIST\n");
        return NULL;
    }
    struct icmphdr *icmph = (struct icmphdr*)(buf + *buf_offset);
    return icmph;
}

// функции, выводящие заголовки соответствующих протоколов
void print_icmp_header(const struct icmphdr *icmph) {
    printf("------------ICMP HEADER------------\n");
    printf("Type                : %u\n", icmph->type);
    printf("Code                : %u\n", icmph->code);
    printf("Checksum            : %u\n", icmph->checksum);
    printf("Un id echo id       : %u\n", icmph->un.echo.id);
    printf("Un id echo sequence : %u\n", icmph->un.echo.sequence);
    printf("Un gateway          : %u\n", icmph->un.gateway);
    printf("Un frag _unused     : %u\n", icmph->un.frag.__unused);
    printf("Un frag mtu         : %u\n", icmph->un.frag.mtu);
    printf("-----------------------------------\n");
}

void print_igmp_header(){
    printf("-----------IGMP PROTOCOL-----------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_ipip_header(){
    printf("-----------IPIP PROTOCOL-----------\n");
    printf("\n");
    printf("-----------------------------------\n");    
}

struct tcphdr * find_tcp_header(unsigned char *buf, long *buf_len, long *buf_offset){
    if(*buf_len <= (long)sizeof(struct tcphdr)) {
        printf("TCP DATA NONEXIST\n");
        return NULL;
    }
    struct tcphdr *tcph = (struct tcphdr*)(buf + *buf_offset);
    *buf_offset += (tcph->doff)*4;
    *buf_len -= (tcph->doff)*4;
    return tcph;
}

void print_tcp_header(const struct tcphdr *tcph) {
    printf("------------TCP HEADER-------------\n");
    printf("Source port         : %u\n", ntohs(tcph->source));
    printf("Detsination port    : %u\n", ntohs(tcph->dest));
    printf("Sequence            : %u\n", ntohs(tcph->seq));
    printf("Acknowledgment      : %u\n", ntohs(tcph->ack_seq));
    printf("Header length       : %u\n", tcph->doff);
    printf("Window size         : %u\n", ntohs(tcph->window));
    printf("Check sum           : %u\n", ntohs(tcph->check));
    printf("-----------------------------------\n");
}

void print_egp(){
    printf("-----------EGP PROTOCOL------------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_pup(){
    printf("-----------PUP PROTOCOL------------\n");
    printf("\n");
    printf("-----------------------------------\n");    
}

struct udphdr * find_udp_header(unsigned char *buf, long *buf_len, long *buf_offset){
    if(*buf_len <= (long)sizeof(struct udphdr)) {
        printf("UDP DATA NONEXIST\n");
        return NULL;
    }

    struct udphdr *udph = (struct udphdr*)(buf + *buf_offset);
    *buf_offset += sizeof(struct udphdr);
    *buf_len -= sizeof(struct udphdr);
    return udph;
}

void print_udp_header(struct udphdr *udph){
    printf("------------UDP HEADER-------------\n");
    printf("Source port         : %u\n", ntohs(udph->source));
    printf("Detsination port    : %u\n", ntohs(udph->dest));
    printf("Length              : %u\n", ntohs(udph->len));
    printf("Check sum           : %u\n", ntohs(udph->check));
    printf("-----------------------------------\n");
}

void print_idp(){
    printf("-----------IDP PROTOCOL------------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_tp(){
    printf("------------TP PROTOCOL------------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_dccp(){
    printf("-----------DCCP PROTOCOL-----------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_rsvp(){
    printf("-----------RSVP PROTOCOL-----------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_gre(){
    printf("-----------GRE PROTOCOL-----------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_esp(){
    printf("-----------ESP PROTOCOL------------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_ah(){
    printf("-----------AH PROTOCOL-------------\n");
    printf("\n");
    printf("-----------------------------------\n"); 
}

void print_mtp(){
    printf("-----------MTP PROTOCOL------------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_beetph(){
    printf("-----------BEETPH PROTOCOL---------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_encap(){
    printf("-----------ENCAP PROTOCOL----------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_pim(){
    printf("-----------PIM PROTOCOL------------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_comp(){
    printf("-----------COMP PROTOCOL-----------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_sctp(){
    printf("-----------SCTP PROTOCOL-----------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_udplite(){
    printf("-----------UDPLITE PROTOCOL--------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_mpls(){
    printf("-----------MPLS PROTOCOL-----------\n");
    printf("\n");
    printf("-----------------------------------\n");
}

void print_ethernet(){
    printf("-----------RAW PACKET--------------\n");
    printf("\n");
    printf("-----------------------------------\n");
}


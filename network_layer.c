#include "include/network_layer.h"

/*
    функции для заполнения и вывода структур протоколов уровня интернет
*/

// функция принимает пакет и его длину и смещение в виде указателей
// она заполняет структуру заголовка и изменяет длину непрочитанных данных и смещение 
struct iphdr * find_ip_header(unsigned char *buf, long *buf_len, long *buf_offset){
    if(*buf_len <= (long)sizeof(struct iphdr)) {
            printf("IP DATA NONEXIST\n");
            return NULL;
        }
    struct iphdr *iph = (struct iphdr *)(buf + *buf_offset);
    *buf_offset += (iph->ihl)*4;
    *buf_len -= (iph->ihl)*4;
    return iph;
}

// функция просто выводит данные структуры
void print_iphdr(const struct iphdr *iph) {
    unsigned char sip[INET_ADDRSTRLEN];
    unsigned char dip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, (char *)sip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->daddr, (char *)dip, INET_ADDRSTRLEN);

    printf("-------------IP HEADER-------------\n");
    printf("IP header length    : %u\n", iph->ihl);
    printf("IP version          : %u\n", iph->version);
    printf("Type of service     : %u\n", iph->tos);
    printf("Total length        : %u\n", ntohs(iph->tot_len));
    printf("Package ID          : %u\n", ntohs(iph->id));
    printf("Time to life        : %u\n", iph->ttl);
    printf("Protocol            : %u\n", iph->protocol);
    printf("Check sum           : %u\n", ntohs(iph->check));
    printf("Send address        : %s\n", sip);
    printf("Destination address : %s\n", dip);
}
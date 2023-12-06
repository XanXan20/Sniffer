#include "include/net_access_layer.h"

/*
    функции для заполнения и вывода структур протоколов уровня сетевого доступа
*/

// функция принимает пакет и его длину и смещение в виде указателей
// она заполняет структуру заголовка и изменяет длину непрочитанных данных и смещение 
struct ethhdr * find_eth_header(unsigned char *buf, long *buf_len, long *buf_offset){
    if(*buf_len <= (long)sizeof(struct ethhdr)) {
            printf("ETHERNET DATA NONEXIST\n");
            return NULL;
        }
        struct ethhdr *ethh = (struct ethhdr *)buf + *buf_offset;
        *buf_offset += sizeof(struct ethhdr);
        *buf_len -= sizeof(struct ethhdr);
        return ethh;
}

// функция просто выводит данные структуры
void print_ethhdr(const struct ethhdr *ethh) {
    printf("\n----------ETHERNET HEADER----------\n");
    printf("Destination MAC     : %02X%02X:%02X%02X:%02X%02X\n", ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2], ethh->h_dest[3], ethh->h_dest[4], ethh->h_dest[5]);
    printf("Source MAC          : %02X%02X:%02X%02X:%02X%02X\n", ethh->h_source[0], ethh->h_source[1], ethh->h_source[2], ethh->h_source[3], ethh->h_source[4], ethh->h_source[5]);
    printf("Ethernet Type       : 0x%04X\n", ntohs(ethh->h_proto));
}
#include "include/application_layer.h"

// HTTP FUCTIONS /////////////////
char check_http(unsigned char *buf, long *buf_offset){
    
    // проверка на то, что пакет http
    if(memcmp(buf + *buf_offset, "GET", 3) == 0 
    || memcmp(buf + *buf_offset, "PUT", 3) == 0
    || memcmp(buf + *buf_offset, "POST", 4) == 0
    || memcmp(buf + *buf_offset, "DELETE", 6) == 0
    || memcmp(buf + *buf_offset, "HTTP", 4) == 0) {
        
        // проверка на тип содержимого пакета
        if(strstr((char *)buf + *buf_offset, "Content-Type: text/") != NULL) return 0;
        else{
            printf("UNSUPPORTED DATA TYPE\n");
            return -1;
        }
    }
    else{
        printf("IT IS NOT HTTP PACKET");
        return -1;
    }
}

//функция вывода данных буффера
void print_payload(unsigned char *buf, int buf_len) {
    for (int i = 0; i < buf_len; i++) {
        printf("%c", buf[i]);
    }
    printf("\n");
}

// вывод данных текстового http пакета
void print_text_http(unsigned char *buf, int buf_len) {
    printf("------------HTTP HEADER------------\n");
    print_payload(buf, buf_len);
    printf("-----------------------------------\n\n");
}
//////////////////////////////////


//  DNS FUNCTIONS  ///////////////

// функция принимает пакет и его длину и смещение в виде указателей
// она заполняет структуру заголовка и изменяет длину непрочитанных данных и смещение 
struct dnshdr * find_dns_header(unsigned char *buf, long *buf_len, long *buf_offset){
    if(*buf_len <= (long)sizeof(struct dnshdr)){
        printf("DNS HEADER NONEXIST\n");
        return NULL;
    }

    struct dnshdr *dnsh = (struct dnshdr*)(buf + *buf_offset);
    *buf_offset += sizeof(struct dnshdr);
    *buf_len -= sizeof(struct dnshdr);

    return dnsh;
}

// подготовка данных dns заголовка для дальнейшей работы в хостовом порядке
void prepare_dns_header(struct dnshdr *dnsh) {
    dnsh->id = ntohs(dnsh->id);
    dnsh->qdcount = ntohs(dnsh->qdcount);
    dnsh->ancount = ntohs(dnsh->ancount);
    dnsh->nscount = ntohs(dnsh->nscount);
    dnsh->arcount = ntohs(dnsh->arcount);
}

void print_dns_header(struct dnshdr *dnsh) {

    prepare_dns_header(dnsh);

    printf("-------------DNS HEADER------------\n");
    printf("ID                  : %u\n\n", dnsh->id);

    printf("QR                  : %u\n", dnsh->qr);
    printf("OPCODE              : %u\n", dnsh->opcode);
    printf("AA                  : %u\n", dnsh->aa);
    printf("TC                  : %u\n", dnsh->tc);
    printf("RD                  : %u\n", dnsh->rd);
    printf("RA                  : %u\n", dnsh->ra);
    printf("Z                   : %u\n", dnsh->z);
    printf("RCODE               : %u\n\n", dnsh->rcode);

    printf("QDCOUNT             : %u\n", dnsh->qdcount);
    printf("ANCOUNT             : %u\n", dnsh->ancount);
    printf("NSCOUNT             : %u\n", dnsh->nscount);
    printf("ARCOUNT             : %u\n", dnsh->arcount);
}

// функция принимает содержимое dns пакета и выводит имя первой секции при помощи первого байта 
uint8_t print_section_name(unsigned char *buf) {
    // берется первый байт данных, в котором содержится информация о длине имени секции
    uint8_t first_byte = *buf;
    uint32_t offset = 1;
    uint8_t *name = buf + offset;
    uint8_t len = 0;

    // вычисляется значение первых двух битов и длина имени секции
    uint8_t label = (first_byte & 0xC0) >> 6;
    if(label == 3) {
        printf("archived label\n");
    }
    else if(label == 0){
        len = first_byte & 0x3F;
    }

    // выводится имя секции по вычисленной длине
    if(len > 0){
        printf("Data                : ");
        for(int j = 0; j <= len; j++) {
            printf("%c", (char)name[j]);
        }
    }
    else printf("Section length is 0\n");

    printf("\n");
    return offset + 1;
}

// функция принимает заголовок dns, пакет и его длину и смещение в виде указателей на переменные
// после чего выводит данные о каждой секции, при этом изменяя данные о длине непрочитанной части пакета и ее смещении 
void print_dns_data(const struct dnshdr *dnsh, unsigned char *buf, long *buf_len, long *buf_offset) {
    if(dnsh->qdcount > 0) {
        printf("------------QUESTION SECTION-------\n");
        for(int i = 0; i < dnsh->qdcount; i++) {
            uint8_t offset = print_section_name(buf + *buf_offset);
            *buf_offset += offset;
            *buf_len -= offset;

            struct dns_qsection *qsec = (struct dns_qsection *)(buf + *buf_offset);

            *buf_offset += sizeof(struct dns_qsection);
            *buf_len -= sizeof(struct dns_qsection);

            printf("Question class       : 0x%04X\n", ntohs(qsec->class));
            printf("Question type        : 0x%04X\n", ntohs(qsec->type));
            printf("-----------------------------------\n");
        }
    }
    else return;
    if(dnsh->ancount > 0) {
        printf("------------ANSWER SECTION---------\n");
        for(int i = 0; i < dnsh->ancount; i++) {
            uint8_t offset = print_section_name(buf + *buf_offset);
            *buf_offset += offset;
            *buf_len -= offset;

            struct dns_ansection *ansec = (struct dns_ansection *)(buf + *buf_offset);

            *buf_offset += sizeof(struct dns_qsection);
            *buf_len -= sizeof(struct dns_qsection);

            printf("Answer type         : 0x%04X\n", ntohs(ansec->type));
            printf("Answer class        : 0x%04X\n", ntohs(ansec->class));
            printf("Answer ttl          : %u\n", ntohs(ansec->ttl));
            printf("Answer data_len     : %u\n", ntohs(ansec->data_len));
            
            *buf_len -= ntohs(ansec->data_len);
            *buf_offset += ntohs(ansec->data_len);
            
            printf("-----------------------------------\n");
        }
    }
    if(dnsh->nscount > 0) {
        printf("----------AUTHORITY SECTION--------\n");
        for(int i = 0; i < dnsh->nscount; i++) {
            uint8_t offset = print_section_name(buf + *buf_offset);
            *buf_offset += offset;
            *buf_len -= offset;

            struct dns_nssection *nssec = (struct dns_nssection *)(buf + *buf_offset);

            *buf_offset += sizeof(struct dns_qsection);
            *buf_len -= sizeof(struct dns_qsection);

            printf("Autority type       : 0x%04X\n", ntohs(nssec->type));
            printf("Autority class      : 0x%04X\n", ntohs(nssec->class));
            printf("Autority ttl        : %u\n", ntohs(nssec->ttl));
            printf("Autority data_len   : %u\n", ntohs(nssec->data_len));
            
            *buf_len -= ntohs(nssec->data_len);
            *buf_offset += ntohs(nssec->data_len);
            
            printf("-----------------------------------\n");
        }
    }
    if(dnsh->arcount > 0) {
        printf("----------ADDITIONAL SECTION-------\n");
        for(int i = 0; i < dnsh->arcount; i++) {
            uint8_t offset = print_section_name(buf + *buf_offset);
            *buf_offset += offset;
            *buf_len -= offset;

            struct dns_arsection *arsec = (struct dns_arsection *)(buf + *buf_offset);

            *buf_offset += sizeof(struct dns_qsection);
            *buf_len -= sizeof(struct dns_qsection);

            printf("Autority type       : 0x%04X\n", ntohs(arsec->type));
            printf("Autority class      : 0x%04X\n", ntohs(arsec->class));
            printf("Autority ttl        : %u\n", ntohs(arsec->ttl));
            printf("Autority data_len   : %u\n", ntohs(arsec->data_len));
            
            *buf_len -= ntohs(arsec->data_len);
            *buf_offset += ntohs(arsec->data_len);
            
            printf("-----------------------------------\n");
        }
    }
}
//////////////////////////////////
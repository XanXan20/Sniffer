#include <sys/socket.h>
#include <string.h>
#include <linux/if_ether.h>
#include <stdlib.h>

#include "include/net_access_layer.h"
#include "include/network_layer.h"
#include "include/transport_layer.h"
#include "include/application_layer.h"

#define HTTP_PORT htons(80)
#define DNS_PORT htons(53)
#define BUF_LEN 65536

int main()
{
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sockfd == -1) {
        perror("socket failed");
        return 1;
    }


    while(1){
        unsigned char *buf = malloc(BUF_LEN);
        long buf_offset = 0;

        ssize_t buf_len = recv(sockfd, buf, BUF_LEN, 0);
        if(buf_len == -1 || buf_len == 0) {
            perror("recv failed");
            return 1;
        }

        struct ethhdr *ethh = find_eth_header(buf, &buf_len, &buf_offset);
        if(ethh == NULL) continue;
        print_ethhdr(ethh);

        struct iphdr *iph = find_ip_header(buf, &buf_len, &buf_offset);
        if(iph == NULL) continue;
        print_iphdr(iph);

        // Проверка содержимого  протокола транспортного уровня
        switch(iph->protocol){
            case IPPROTO_ICMP:
                struct icmphdr *icmph = find_icmp_header(buf, &buf_len, &buf_offset);
                if(icmph == NULL) continue;
                print_icmp_header(icmph);
                break;
                
            case IPPROTO_IGMP:
                print_igmp_header();
                break;

            case IPPROTO_IPIP:
                print_ipip_header();
                break;

            case IPPROTO_TCP:
                struct tcphdr *tcph = find_tcp_header(buf, &buf_len, &buf_offset);
                if(tcph == NULL) continue;
                print_tcp_header(tcph);
                
                // проверка на наличие сожержимого в протоколе транспортного уровня
                if(buf_len > 0) {

                    // проверка порта, для того чтобы понять какие протоколы могли придти
                    if(tcph->dest == HTTP_PORT || tcph->source == HTTP_PORT) {
                        
                        //проверка на то, какой протокол содержится в пакете
                        char http_check_res = check_http(buf, &buf_offset);
                        switch(http_check_res){
                            case 0:
                                print_text_http(buf + buf_offset, buf_len);
                                break;
                            default:
                                printf("UNSUPPORTABLE DATA TYPE");
                                break;
                        }
                    }
                }
                break;

            case IPPROTO_EGP:
                print_egp();
                break;

            case IPPROTO_PUP:
                print_pup();
                break;

            case IPPROTO_UDP:
                struct udphdr *udph = find_udp_header(buf, &buf_len, &buf_offset);
                if(udph == NULL) continue;
                print_udp_header(udph);

                // проверка на наличие сожержимого в протоколе транспортного уровня
                if(buf_len > 0){
                    
                    // проверка порта, для того чтобы понять какие протоколы могли придти
                    if(udph->source == DNS_PORT || udph->dest == DNS_PORT) {
                        // к сожалению, проверку на dns пакет реализовать не смог
                        struct dnshdr *dnsh = find_dns_header(buf, &buf_len, &buf_offset);
                        if(dnsh == NULL) continue;

                        print_dns_header(dnsh);
                        print_dns_data(dnsh, buf, &buf_len, &buf_offset);
                    }
                }
                break;

            case IPPROTO_IDP:
                print_idp();
                break;

            case IPPROTO_TP:
                print_tp();
                break;

            case IPPROTO_DCCP:
                print_dccp();
                break;

            case IPPROTO_RSVP:
                print_rsvp();
                break;            

            case IPPROTO_GRE:
                print_gre();
                break;

            case IPPROTO_ESP:
                print_esp();
                break;

            case IPPROTO_AH:
                print_ah();
                break;

            case IPPROTO_MTP:
                print_mtp();
                break;

            case IPPROTO_BEETPH:
                print_beetph();
                break;

            case IPPROTO_ENCAP:
                print_encap();
                break;

            case IPPROTO_PIM:
                print_pim();
                break;

            case IPPROTO_COMP:
                print_comp();
                break;

            case IPPROTO_SCTP:
                print_sctp();
                break;

            case IPPROTO_UDPLITE:
                print_udplite();
                break;

            case IPPROTO_MPLS:
                print_mpls();
                break;

            case IPPROTO_ETHERNET:
                print_ethernet();
                break;

            default:
                printf("Unknown protocol\n");
                break;
        }

        free(buf);
    }
    return 0;
}


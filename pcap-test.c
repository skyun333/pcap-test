#include <stdio.h>
#include <pcap.h>
#include <stdbool.h>
#include<netinet/in.h>
#include <stdlib.h>
#include <string.h>



void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];/* destination ethernet address */
    u_int8_t  ether_shost[6];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif#include<netinet/in.h>
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

Param param  = {
    .dev_ = NULL
};

void print_eth(const u_char * packet){
    int i;
    struct libnet_ethernet_hdr *res=(struct libnet_ethernet_hdr*)(packet);

    printf("\n======== Ethernet header ========\n");
    for(i=0;i<6;i++){
        res->ether_dhost[i]=packet[i];
        res->ether_shost[i]=packet[i+6];
    }
    printf("ether_shost - ");
    for(i=0;i<6;i++){
        printf("%x",res->ether_shost[i]);
        if(i!=5){
            printf(":");
        }
    }
    printf("\n");
    printf("ether_dhost - ");
    for(i=0;i<6;i++){
        printf("%x",res->ether_dhost[i]);
        if(i!=5){
            printf(":");
        }
    }
}

void print_ip(const u_char * packet){
    int i;
    printf("\n======== IP header ========");
    printf("\nsource address - ");
    for(i=0;i<4;i++){
        printf("%d",packet[26+i]);
        if(i!=3){
            printf(".");
        }
    }
    printf("\ndestination address - ");
    for(i=0;i<4;i++){
        printf("%d",packet[30+i]);
        if(i!=3){
            printf(".");
        }
    }
    printf("\n");
}

void print_tcp(const u_char * packet){
    printf("======== TCP header ========\n");
    struct libnet_tcp_hdr *res=(struct libnet_tcp_hdr*)(packet);
    res->th_sport=(packet[34]<<8)+packet[35];
    res->th_dport=(packet[36]<<8)+packet[37];
    printf("src port - %d \n",res->th_sport);
    printf("dst port - %d \n",res->th_dport);
}

void print_data(const u_char *packet){
    printf("======== Payload Data ========\n");
    int i;
    for(i=0;i<8;i++){
        printf("%02x ",packet[66+i]);
    }
    printf("\n\n");
}

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}



int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);//packet -> start , header -> length
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);
        print_eth(packet);
        print_ip(packet);
        print_tcp(packet);
        print_data(packet);
    }

    pcap_close(pcap);
}


/***********code review*****************/
// inet_ntoa와 inet_ntop 사용해보기
// data 출력 시 -> tcp 데이터의 길이를 구하는 공식을 이용하여 출력해야 함.
// 위 코드는 각 필드의 위치가 하드 코딩 된 코드
// 위치와 길이를 각 필드에서 *4와 같은 연산을 통해 찾아내서 계산하도록.

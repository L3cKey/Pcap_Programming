#ifndef MYHEADER_H
#define MYHEADER_H

#include <netinet/in.h>

/* Ethernet Header */
struct ethheader {
    unsigned char ether_dhost[6];  /* Destination MAC address */
    unsigned char ether_shost[6];  /* Source MAC address */
    unsigned short ether_type;     /* Type: IP, ARP, etc. */
};

/* IP Header */
struct ipheader {
    unsigned char iph_ihl:4,     /* IP header length */
                  iph_ver:4;     /* IP version */
    unsigned char iph_tos;       /* Type of service */
    unsigned short iph_len;      /* Total packet length (header + data) */
    unsigned short iph_ident;    /* Identification */
    unsigned short iph_flag:3,   /* Fragmentation flags */
                       iph_offset:13; /* Flags offset */
    unsigned char iph_ttl;       /* Time to live */
    unsigned char iph_protocol;  /* Protocol type */
    unsigned short iph_chksum;   /* Checksum */
    struct in_addr iph_sourceip; /* Source IP address */
    struct in_addr iph_destip;   /* Destination IP address */
};

/* TCP Header */
struct tcpheader {
    unsigned short tcp_sport;    /* Source port */
    unsigned short tcp_dport;    /* Destination port */
    unsigned int   tcp_seq;      /* Sequence number */
    unsigned int   tcp_ack;      /* Acknowledgement number */
    unsigned char  tcp_offx2;    /* Data offset (upper 4비트) + reserved (lower 4비트) */
    unsigned char  tcp_flags;    /* TCP flags */
    unsigned short tcp_win;      /* Window size */
    unsigned short tcp_sum;      /* Checksum */
    unsigned short tcp_urp;      /* Urgent pointer */
};

/* TCP 헤더의 길이를 추출하는 매크로 (상위 4비트 사용) */
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)

#endif


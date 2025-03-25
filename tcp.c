#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

// MAC 주소를 16진수 형식으로 출력하는 함수
void print_mac(u_char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5)
            printf(":");
    }
}

// 패킷 캡처 시 호출되는 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Ethernet 헤더 추출
    struct ethheader *eth = (struct ethheader *)packet;
    printf("[Ethernet] Source MAC: ");
    print_mac(eth->ether_shost);
    printf("\n");
    
    printf("[Ethernet] Destination MAC: ");
    print_mac(eth->ether_dhost);
    printf("\n");

    // IP 패킷인지 확인 (0x0800는 IP의 EtherType)
    if (ntohs(eth->ether_type) == 0x0800) {
        // Ethernet 헤더 뒤의 IP 헤더 위치 계산
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        // IP 헤더의 실제 길이 (iph_ihl 필드는 4바이트 단위)
        int ip_header_len = ip->iph_ihl * 4;
        
        printf("[IP] Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("[IP] Destination IP: %s\n", inet_ntoa(ip->iph_destip));

        // TCP 프로토콜에 한정하여 처리
        if (ip->iph_protocol == IPPROTO_TCP) {
            // IP 헤더 길이를 고려하여 TCP 헤더의 위치 계산
            struct tcpheader *tcp = (struct tcpheader *)((u_char*)ip + ip_header_len);
            // TCP 헤더 길이 계산 (4바이트 단위)
            int tcp_header_len = TH_OFF(tcp) * 4;
            
            printf("[TCP] Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("[TCP] Destination Port: %d\n", ntohs(tcp->tcp_dport));

            // TCP 페이로드(메시지)의 시작 위치 및 길이 계산
            u_char *payload = (u_char *)tcp + tcp_header_len;
            int total_ip_length = ntohs(ip->iph_len);
            int payload_length = total_ip_length - ip_header_len - tcp_header_len;

            if (payload_length > 0) {
                // 페이로드를 최대 16바이트까지만 출력
                int print_len = payload_length < 16 ? payload_length : 16;
                printf("[Message] (최대 %d byte):\n", print_len);
                for (int i = 0; i < print_len; i++) {
                    printf("%02x ", payload[i]);
                }
                printf("\n");
            } else {
                printf("[Message] No payload\n");
            }
            printf("---------- Protocol: TCP ----------\n\n");
        }
        else {
            // TCP가 아닌 패킷은 무시
            printf("---------- Protocol: Non-TCP Packet ----------\n\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP 패킷만 캡처
    bpf_u_int32 net;

    // 1단계: pcap 세션 생성 (네트워크 인터페이스: eth0)
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // 2단계: BPF 필터 컴파일 및 적용
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_perror(handle, "Error setting filter");
        exit(EXIT_FAILURE);
    }

    // 3단계: 패킷 캡처 시작 (무한 루프)
    pcap_loop(handle, -1, got_packet, NULL);

    // 4단계: pcap 세션 종료
    pcap_close(handle);
    return 0;
}


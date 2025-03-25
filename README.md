# Pcap_Programming

# 이 문서에서는 C/C++ 기반 PCAP API를 활용하여 TCP 패킷의 정보를 출력하는 프로그램 작성 과제에 대해 설명합니다. 프로그램은 Ethernet, IP, TCP 헤더 정보를 출력하고, 패킷의 payload(메시지)를 일부 출력하도록 구성됩니다. (UDP 패킷은 필터를 통해 무시)

# 요구사항
## 헤더 정보 출력

Ethernet Header: 출발지 MAC 주소와 목적지 MAC 주소

IP Header: 출발지 IP와 목적지 IP

IP 헤더 길이(ip_hl)를 활용하여 실제 헤더 크기를 계산

TCP Header: 출발지 포트와 목적지 포트

TCP 헤더 길이(doff)를 활용하여 실제 헤더 크기를 계산

Payload 출력

IP와 TCP 헤더 뒤에 오는 데이터를 메시지로 간주

데이터 길이가 긴 경우 적당한 길이(예: 최대 16바이트)만 출력

프로그램 대상

TCP 패킷만을 처리 (UDP 패킷은 무시)


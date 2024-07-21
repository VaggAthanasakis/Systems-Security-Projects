#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <signal.h>
#include <gmp.h>

// Global variable declaration
int numOfFlows = 0;
int numOfTCPFlows = 0;
int numOfUDPFlows = 0;
int numOfTCP = 0; // tcp packets
int numOfUDP = 0; // udp packets
int totalNumOfPackets = 0;
mpz_t totalBytesTCP;
mpz_t totalBytesUDP;

// Structure to represent a flow
struct Flow {
    char* src_ip;
    char* dst_ip;
    int src_port;
    int dst_port;
};

struct Flow uniqueFlows[10000];


/*************************************/
// Prints statistics
void printStatistics(){
    totalNumOfPackets += numOfTCP + numOfUDP;
    printf("\nTotal number of network flows captured: %d\n",numOfFlows);
    printf("Number of TCP network flows captured: %d\n",numOfTCPFlows);
    printf("Number of UDP network flows captured: %d\n",numOfUDPFlows);
    printf("Total number of packets received (include the skipped packets, that weren’t TCP or UDP packets): %d\n",totalNumOfPackets);
    printf("Total number of TCP packets received: %d\n",numOfTCP);
    printf("Total number of UDP packets received: %d\n",numOfUDP);
    gmp_printf("Total bytes of TCP packets received: %Zd\n",totalBytesTCP);
    gmp_printf("Total bytes of UDP packets received: %Zd\n",totalBytesUDP);
    fflush(stdout);

}

/*********************************************************************************************/
void checkFlow(int src_port, int dst_port, char* src_IP, char* dst_IP, char* protocol){

    //size_t flowsArraySize = sizeof(uniqueFlows) / sizeof(uniqueFlows[0]);

    for (int i = 0; i < numOfFlows; ++i) { //Compare to every flow in the array
        if (src_port== uniqueFlows[i].src_port && dst_port == uniqueFlows[i].dst_port && strcmp(src_IP, uniqueFlows[i].src_ip) == 0 && strcmp(dst_IP, uniqueFlows[i].dst_ip) == 0) {
            //If flow exists in the array already dont keep searching             
            return;
        }
    }

    //else since flow does not exist in the array add flow to the last position of the array
    struct Flow newFlow = {src_IP, dst_IP, src_port, dst_port};
    uniqueFlows[numOfFlows] = newFlow;
    numOfFlows++; 

    if(strcmp(protocol, "UDP") == 0){
        numOfUDPFlows++;
    }else if(strcmp(protocol, "TCP") == 0){
        numOfTCPFlows++;
    }else{
        fflush(stdout);
    }
    return ; 
}

void packet_handler_online(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet){

    FILE* log = fopen("log.txt", "a");
    unsigned int *int_ptr = (unsigned int *)user_data;
    int filter = *int_ptr; // take the number of the port that is given as a filter
    int ethHeaderSize = 14;                                      // The ethernet header that pcap_loop captures is 14 bytes long and is fixed size
                                                                 // The captured pachet structure will be something like this:
                                                                /*  +---------------------+
                                                                    |  Ethernet Header    |
                                                                    +---------------------+
                                                                    |  IP Header          |
                                                                    +---------------------+
                                                                    |  Transport Layer    |
                                                                    |  (e.g., TCP/UDP)    |
                                                                    +---------------------+
                                                                    |  Application Layer  |
                                                                    +---------------------+*/
    
    const struct ip * ip_head = (struct ip *)(packet + ethHeaderSize);  // We move past the ethernet header to get to the ip header
    
    // Take the packet's ip address and port (source & destination)
    

    size_t ipHeaderSize = ip_head->ip_hl << 2;  // Header length in bytes

    // IPv4 Packet-------------------------------------------------------------
    if (ip_head->ip_v == 4) { // check if the packet is IPv4
        if (ip_head->ip_p == IPPROTO_TCP){ // check if we have a tcp packet
            
            
            struct tcphdr *tcp_head = (struct tcphdr *)((uint8_t *)ip_head + ipHeaderSize);
            
            int sourcePort = tcp_head->th_sport;
            int destPort = tcp_head->th_dport;
            // apply the filter
            if(filter !=0 && destPort != filter ){
                //printf("\nFiltered");
                fclose(log);
                return;
            }

            numOfTCP++;

            fprintf(log,"Source Port (TCP): %u\n", ntohs(sourcePort));
            fprintf(log,"Destination Port (TCP): %u\n", ntohs(destPort));

            // ip addresses
            char ip_source_string[INET6_ADDRSTRLEN];
            char ip_dst_string[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip_head->ip_src, ip_source_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6,&ip_head->ip_dst, ip_dst_string, INET6_ADDRSTRLEN);

            fprintf(log,"Source Address (TCP): %s\n", ip_source_string);
            fprintf(log,"Destination Address (TCP): %s\n", ip_dst_string);

           
            fprintf(log,"Protocol: IPv4\n");
            // 8) header length & payload length in bytes.
            size_t tcpHeaderLength = tcp_head->th_off << 2;
            size_t tcpPayloadLength = ntohs(ip_head->ip_len) - ipHeaderSize - tcpHeaderLength;
            fprintf(log,"TCP Header Length: %zu bytes\n", tcpHeaderLength);
            fprintf(log,"TCP Payload Length: %zu bytes\n", tcpPayloadLength);

           
            mpz_add_ui(totalBytesTCP, totalBytesTCP, tcpHeaderLength);
            mpz_add_ui(totalBytesTCP, totalBytesTCP, tcpPayloadLength);


            // 9) Finding where the payload is located in the memory
            // Calculate TCP payload pointer 
            size_t payloadOffset = ethHeaderSize + ipHeaderSize + tcpHeaderLength;
            const unsigned char *payload_address = packet + payloadOffset;
            fprintf(log,"Address of payload in memory: %p \n", (void *)payload_address);

            // 10) Retransmition 
            if (tcp_head->th_flags & TH_RST) { //This is a bitwise AND operation with the bitmask TH_RST (0x04)
                fprintf(log,"Retransmitted: YES\n\n");
            } 
            else {
                fprintf(log,"Retransmitted: NO\n\n");
            }

            checkFlow(sourcePort,destPort,ip_source_string,ip_dst_string,"TCP");
        }
        else if(ip_head->ip_p == IPPROTO_UDP){ 
            // we have a UDP packet
            
          
            struct udphdr *udp_head = (struct udphdr *)((uint8_t *)ip_head + ipHeaderSize);
             
            int sourcePort = udp_head->uh_sport;
            int destPort = udp_head->uh_dport;

            // apply the filter
            if(filter !=0 && destPort != filter ){
                //printf("\nFiltered\n");
                fclose(log);
                return;
            }
            numOfUDP++;

            fprintf(log,"Source Port (UDP): %u\n", ntohs(sourcePort));
            fprintf(log,"Destination Port (UDP): %u\n", ntohs(destPort));

            char ip_source_string[INET6_ADDRSTRLEN];
            char ip_dst_string[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip_head->ip_src), ip_source_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip_head->ip_dst), ip_dst_string, INET6_ADDRSTRLEN);

            fprintf(log,"Source Address (UDP): %s\n", ip_source_string);
            fprintf(log,"Destination Address (UDP): %s\n", ip_dst_string);

            
            fprintf(log,"Protocol: IPv4\n");

            // 8) header length & payload length in bytes.
            size_t udpHeaderLength = sizeof(struct udphdr);  

            size_t udpPayloadLength = ntohs(ip_head->ip_len) - ipHeaderSize - udpHeaderLength;
            fprintf(log,"UDP Header Length: %zu bytes\n", udpHeaderLength);
            fprintf(log,"UDP Payload Length: %zu bytes\n", udpPayloadLength);

            
            mpz_add_ui(totalBytesUDP, totalBytesUDP, udpHeaderLength);
            mpz_add_ui(totalBytesUDP, totalBytesUDP, udpPayloadLength);
            
            // 9) Finding where the payload is located in the memory
            size_t payloadOffset = ethHeaderSize + ipHeaderSize + udpHeaderLength;
            const unsigned char *payload_address = packet + payloadOffset;
            fprintf(log,"Address of payload in memory: %p \n\n", (void *)payload_address); 
            
            checkFlow(sourcePort,destPort,ip_source_string,ip_dst_string,"UDP");
        }
        else{
            // other type of packet
            //printf("\nOther Type Of packet: %u\n", ip_head->ip_p);
            totalNumOfPackets++;
        }

    }

    // IPV6 Packet-------------------------------------------------------------
    else if(ip_head->ip_v == 6) {  // check if the packet is IPv6
        struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet + 14);

        // Extract the next header value
        unsigned int next_header = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        size_t ipv6HeaderSize = 40;  // Header length in bytes is fixed for ipv6 protocol

        // TCP
        if (next_header == IPPROTO_TCP) {
            //printf("TCP Packet captured\n");
            struct tcphdr *tcp_head = (struct tcphdr *)((uint8_t *)ipv6_header+ ipv6HeaderSize);
            
            int sourcePort = tcp_head->th_sport;
            int destPort = tcp_head->th_dport;

            // apply the filter
            if(filter !=0 && destPort != filter ){
                //printf("\nFiltered");
                fclose(log);
                return;
            }
            numOfTCP++;
            fprintf(log,"Source Port (TCP): %u\n", ntohs(sourcePort));
            fprintf(log,"Destination Port (TCP): %u\n", ntohs(destPort));
            
            // convert the address into a string 
            char ipv6_source_string[INET6_ADDRSTRLEN];
            char ipv6_dst_string[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ipv6_source_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ipv6_dst_string, INET6_ADDRSTRLEN);

            fprintf(log,"Source Address (TCP): %s\n", ipv6_source_string);
            fprintf(log,"Destination Address (TCP): %s\n", ipv6_dst_string);
            
            fprintf(log,"Protocol: IPv6\n");
            // 8) header length & payload length in bytes.
            size_t tcpHeaderLength = tcp_head->th_off << 2;
            size_t tcpPayloadLength = ntohs(ipv6HeaderSize/4) - ipv6HeaderSize - tcpHeaderLength;
            fprintf(log,"TCP Header Length: %zu bytes\n", tcpHeaderLength);
            fprintf(log,"TCP Payload Length: %zu bytes\n", tcpPayloadLength);

            // increase the number of total tcp bytes received
            mpz_add_ui(totalBytesTCP, totalBytesTCP, tcpHeaderLength);
            mpz_add_ui(totalBytesTCP, totalBytesTCP, tcpPayloadLength);

            // 9) Finding where the payload is located in the memory
            // Calculate TCP payload pointer 
            size_t payloadOffset = ethHeaderSize + ipv6HeaderSize + tcpHeaderLength;
            const unsigned char *payload_address = packet + payloadOffset;
            
            fprintf(log,"Address of payload in memory: %p \n", (void *)payload_address); 

            // 10) Retransmition 
            if (tcp_head->th_flags & TH_RST) { //This is a bitwise AND operation with the bitmask TH_RST (0x04)
                fprintf(log,"Retransmitted: YES\n\n");
            } 
            else {
                fprintf(log,"Retransmitted: NO\n\n");
            }
            
            checkFlow(sourcePort,destPort,ipv6_source_string,ipv6_dst_string,"TCP");
        } 
        // UDP
        else if (next_header == IPPROTO_UDP) {
             // we have a UDP packet
            struct udphdr *udp_head = (struct udphdr *)((uint8_t *)ipv6_header + ipv6HeaderSize);
             
            int sourcePort = udp_head->uh_sport;
            int destPort = udp_head->uh_dport;

            // apply the filter
            if(filter !=0 && destPort != filter ){
                //printf("\nFiltered");
                fclose(log);
                return;
            }
            numOfUDP++;
            fprintf(log,"Source Port (UDP): %u\n", ntohs(sourcePort));
            fprintf(log,"Destination Port (UDP): %u\n", ntohs(destPort));

            // convert the address into a string 
            char ipv6_source_string[INET6_ADDRSTRLEN];
            char ipv6_dst_string[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ipv6_source_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ipv6_dst_string, INET6_ADDRSTRLEN);

            fprintf(log,"Source Address (UDP): %s\n", ipv6_source_string);
            fprintf(log,"Destination Address (UDP): %s\n", ipv6_dst_string);

            
            fprintf(log,"Protocol: IPv6\n");//

            // 8) header length & payload length in bytes.
            size_t udpHeaderLength = sizeof(struct udphdr);  // UDP header is a fixed size
            
            size_t udpPayloadLength = ntohs(ip_head->ip_len) - ipHeaderSize - udpHeaderLength;
            fprintf(log,"UDP Header Length: %zu bytes\n", udpHeaderLength);
            fprintf(log,"UDP Payload Length: %zu bytes\n", udpPayloadLength);

            // increase the number of total udp bytes received
            mpz_add_ui(totalBytesUDP, totalBytesUDP, udpHeaderLength);
            mpz_add_ui(totalBytesUDP, totalBytesUDP, udpPayloadLength);

            // 9) Finding where the payload is located in the memory
            size_t payloadOffset = ethHeaderSize + ipv6HeaderSize + udpHeaderLength;
            const unsigned char *payload_address = packet + payloadOffset;
            fprintf(log,"Address of payload in memory: %p \n\n", (void *)payload_address); 
            // 12) MARK RETRANSMITTED
            checkFlow(sourcePort,destPort,ipv6_source_string,ipv6_dst_string,"UDP");
        } 
        else {
            //printf("Unknown protocol: %d\n", next_header);
            totalNumOfPackets++; 
        }
        
    }

    fclose(log); // close the log file 
}


/***********************************************************/
void packet_handler_offline(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet){

    unsigned int *int_ptr = (unsigned int *)user_data;
    int filter = *int_ptr; // take the number of the port that is given as a filter
    int ethHeaderSize = 14;                                      // The ethernet header that pcap_loop captures is 14 bytes long and is fixed size
                                                                 // The captured pachet structure will be something like this:
                                                                /*  +---------------------+
                                                                    |  Ethernet Header    |
                                                                    +---------------------+
                                                                    |  IP Header          |
                                                                    +---------------------+
                                                                    |  Transport Layer    |
                                                                    |  (e.g., TCP/UDP)    |
                                                                    +---------------------+
                                                                    |  Application Layer  |
                                                                    +---------------------+*/
    
    const struct ip * ip_head = (struct ip *)(packet + ethHeaderSize);  // We move past the ethernet header to get to the ip header
    
    // Take the packet's ip address and port (source & destination)

    size_t ipHeaderSize = ip_head->ip_hl << 2;  // Header length in bytes

    // IPv4 Packet-------------------------------------------------------------
    if (ip_head->ip_v == 4) { // check if the packet is IPv4
        if (ip_head->ip_p == IPPROTO_TCP){ // check if we have a tcp packet
            struct tcphdr *tcp_head = (struct tcphdr *)((uint8_t *)ip_head + ipHeaderSize);
            
            int sourcePort = tcp_head->th_sport;
            int destPort = tcp_head->th_dport;
            // apply the filter
            if(filter !=0 && destPort != filter ){
                //printf("\nFiltered\n");
                return;
            }

            numOfTCP++;
            printf("Source Port (TCP): %u\n", ntohs(sourcePort));
            printf("Destination Port (TCP): %u\n", ntohs(destPort));

            // ip addresses
            char ip_source_string[INET6_ADDRSTRLEN];
            char ip_dst_string[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip_head->ip_src, ip_source_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6,&ip_head->ip_dst, ip_dst_string, INET6_ADDRSTRLEN);

            printf("Source Address (TCP): %s\n", ip_source_string);
            printf("Destination Address (TCP): %s\n", ip_dst_string);

            //printf("Protocol: TCP\n");
            printf("Protocol: IPv4\n");
            // 8) header length & payload length in bytes.
            size_t tcpHeaderLength = tcp_head->th_off << 2;
            size_t tcpPayloadLength = pkthdr->len - (14 + (ip_head->ip_hl << 2) + tcpHeaderLength);
            printf("TCP Header Length: %zu bytes\n", tcpHeaderLength);
            printf("TCP Payload Length: %zu bytes\n", tcpPayloadLength);

            //totalBytesTCP +=  tcpHeaderLength + tcpPayloadLength;
            mpz_add_ui(totalBytesTCP, totalBytesTCP, tcpHeaderLength);
            mpz_add_ui(totalBytesTCP, totalBytesTCP, tcpPayloadLength);
            

            // 9) Finding where the payload is located in the memory
            // Calculate TCP payload pointer 
            size_t payloadOffset = ethHeaderSize + ipHeaderSize + tcpHeaderLength;
            const unsigned char *payload_address = packet + payloadOffset;
            printf("Address of payload in memory: %p \n", (void *)payload_address);

            // 10) Retransmition 
            if (tcp_head->th_flags & TH_RST) { //This is a bitwise AND operation with the bitmask TH_RST (0x04)
                printf("Retransmitted: YES\n\n");
            } 
            else {
                printf("Retransmitted: NO\n\n");
            }
            checkFlow(sourcePort,destPort,ip_source_string,ip_dst_string,"TCP");
        }
        else if(ip_head->ip_p == IPPROTO_UDP){ 
            // we have a UDP packet
            struct udphdr *udp_head = (struct udphdr *)((uint8_t *)ip_head + ipHeaderSize);
             
            int sourcePort = udp_head->uh_sport;
            int destPort = udp_head->uh_dport;

            // apply the filter
            if(filter !=0 && destPort != filter ){
                //printf("\nFiltered\n");
                return;
            }

            numOfUDP++;
            printf("Source Port (UDP): %u\n", ntohs(sourcePort));
            printf("Destination Port (UDP): %u\n", ntohs(destPort));

            char ip_source_string[INET6_ADDRSTRLEN];
            char ip_dst_string[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip_head->ip_src), ip_source_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip_head->ip_dst), ip_dst_string, INET6_ADDRSTRLEN);

            printf("Source Address (UDP): %s\n", ip_source_string);
            printf("Destination Address (UDP): %s\n", ip_dst_string);

            //printf("Protocol: UDP\n");
            printf("Protocol: IPv4\n");

            // 8) header length & payload length in bytes.
            size_t udpHeaderLength = sizeof(struct udphdr);  // UDP header is a fixed size
            //size_t udpPayloadLength = ntohs(udp_head->len) - udpHeaderLength;
            size_t udpPayloadLength = ntohs(ip_head->ip_len) - ipHeaderSize - udpHeaderLength;
            printf("UDP Header Length: %zu bytes\n", udpHeaderLength);
            printf("UDP Payload Length: %zu bytes\n", udpPayloadLength);

            
            mpz_add_ui(totalBytesUDP, totalBytesUDP, udpHeaderLength);
            mpz_add_ui(totalBytesUDP, totalBytesUDP, udpPayloadLength);
            

            // 9) Finding where the payload is located in the memory
            size_t payloadOffset = ethHeaderSize + ipHeaderSize + udpHeaderLength;
            const unsigned char *payload_address = packet + payloadOffset;
            printf("Address of payload in memory: %p \n\n", (void *)payload_address); 
            
            checkFlow(sourcePort,destPort,ip_source_string,ip_dst_string,"UDP");
        }
        else{
            // other type of packet
            //printf("\nOther Type Of packet: %u\n", ip_head->ip_p);
            totalNumOfPackets++;
        }
    }

    // IPV6 Packet-------------------------------------------------------------
    else if(ip_head->ip_v == 6) {  // check if the packet is IPv6
        struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet + 14);

        // Extract the next header value
        unsigned int next_header = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        size_t ipv6HeaderSize = 40;  // Header length in bytes is fixed for ipv6 protocol

        // TCP
        if (next_header == IPPROTO_TCP) {
            //printf("TCP Packet captured\n");
            
            struct tcphdr *tcp_head = (struct tcphdr *)((uint8_t *)ipv6_header+ ipv6HeaderSize);
            
            int sourcePort = tcp_head->th_sport;
            int destPort = tcp_head->th_dport;

            // apply the filter
            if(filter !=0 && destPort != filter ){
                //printf("\nFiltered");
                return;
            }

            numOfTCP++;
            printf("Source Port (TCP): %u\n", ntohs(sourcePort));
            printf("Destination Port (TCP): %u\n", ntohs(destPort));
            
            // convert the address into a string 
            char ipv6_source_string[INET6_ADDRSTRLEN];
            char ipv6_dst_string[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ipv6_source_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ipv6_dst_string, INET6_ADDRSTRLEN);

            printf("Source Address (TCP): %s\n", ipv6_source_string);
            printf("Destination Address (TCP): %s\n", ipv6_dst_string);
            
            printf("Protocol: IPv6\n");
            // 8) header length & payload length in bytes.
            size_t tcpHeaderLength = tcp_head->th_off << 2;
            size_t tcpPayloadLength =pkthdr->len - (14 + sizeof(struct ip6_hdr) + tcpHeaderLength);
            printf("TCP Header Length: %zu bytes\n", tcpHeaderLength);
            printf("TCP Payload Length: %zu bytes\n", tcpPayloadLength);
            
            //totalBytesTCP += tcpHeaderLength + tcpPayloadLength;
            mpz_add_ui(totalBytesTCP, totalBytesTCP, tcpHeaderLength);
            mpz_add_ui(totalBytesTCP, totalBytesTCP, tcpPayloadLength);


            // 9) Finding where the payload is located in the memory
            // Calculate TCP payload pointer 
            size_t payloadOffset = ethHeaderSize + ipv6HeaderSize + tcpHeaderLength;
            const unsigned char *payload_address = packet + payloadOffset;
            
            printf("Address of payload in memory: %p \n", (void *)payload_address); 

            // 10) Retransmition 
            if (tcp_head->th_flags & TH_RST) { //This is a bitwise AND operation with the bitmask TH_RST (0x04)
                printf("Retransmitted: YES\n\n");
            } 
            else {
                printf("Retransmitted: NO\n\n");
            }
            checkFlow(sourcePort,destPort,ipv6_source_string,ipv6_dst_string,"TCP");

        } 
        // UDP
        else if (next_header == IPPROTO_UDP) {
             // we have a UDP packet
            struct udphdr *udp_head = (struct udphdr *)((uint8_t *)ipv6_header + ipv6HeaderSize);
             
            int sourcePort = udp_head->uh_sport;
            int destPort = udp_head->uh_dport;

            // apply the filter
            if(filter !=0 && destPort != filter ){
                //printf("\nFiltered\n");
                return;
            }
            numOfUDP++;
            printf("Source Port (UDP): %u\n", ntohs(sourcePort));
            printf("Destination Port (UDP): %u\n", ntohs(destPort));

            // convert the address into a string 
            char ipv6_source_string[INET6_ADDRSTRLEN];
            char ipv6_dst_string[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ipv6_source_string, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ipv6_dst_string, INET6_ADDRSTRLEN);

            printf("Source Address (UDP): %s\n", ipv6_source_string);
            printf("Destination Address (UDP): %s\n", ipv6_dst_string);

            //printf("Protocol: UDP\n");
            printf("Protocol: IPv6\n");

            // 8) header length & payload length in bytes.
            size_t udpHeaderLength = sizeof(struct udphdr);  // UDP header is a fixed size
            //size_t udpPayloadLength = ntohs(udp_head->len) - udpHeaderLength;
            size_t udpPayloadLength = ntohs(ip_head->ip_len) - ipHeaderSize - udpHeaderLength;
            printf("UDP Header Length: %zu bytes\n", udpHeaderLength);
            printf("UDP Payload Length: %zu bytes\n", udpPayloadLength);

            
            mpz_add_ui(totalBytesUDP, totalBytesUDP, udpHeaderLength);
            mpz_add_ui(totalBytesUDP, totalBytesUDP, udpPayloadLength);
            

            // 9) Finding where the payload is located in the memory
            size_t payloadOffset = ethHeaderSize + ipv6HeaderSize + udpHeaderLength;
            const unsigned char *payload_address = packet + payloadOffset;
            printf("Address of payload in memory: %p \n\n", (void *)payload_address); 
            
            checkFlow(sourcePort,destPort,ipv6_source_string,ipv6_dst_string,"UDP");
        } 
        else {
            totalNumOfPackets++;
        }
    }
}

/* function to capture online packets */
void onlinePacketMonitoring(char* device,char* string_filter){
    char errbuf[100];
    //We open a device in order to capture packets
    if(device == NULL){
        exit(1);
    }
    // pcap_open_live() is used to obtain a packet capture descriptor to look at packets on the network
    // we use the function's "promiscuous mode", where the interface captures all packets on the network, not just those destined for it
    // we use a 0ms packet block time to get all the packets in the network
    // errbuf is used to return error or warning text
    pcap_t * capture = pcap_open_live(device, BUFSIZ, 1, 0, errbuf);
    
    // check if the pcap_open_live() fails
    if(capture == NULL){
        fprintf(stderr, "Could not start capture: %s\n", errbuf);
        fflush(stdout);
        exit(1);
    }

    // Get any desired filter
    int destport;
    if(string_filter !=  NULL){  
        if (sscanf(string_filter, "port %d", &destport) == 1) {
            // The value was successfully extracted
            printf("Port number: %d\n", destport);
            fflush(stdout);
        }
        else {
            // Extraction failed, handle the error
            fprintf(stderr,"Error extracting port number.\n");
            exit(1);
        }
    }
    else{
        destport = 0;
    }

    fflush(stdout);
    pcap_loop(capture, 0, packet_handler_online, (unsigned char*)&destport);   
    pcap_close(capture); // Stop capturing
}


/* function to capture offline packets */
void offlinePacketMonitoring(char* device,char* string_filter){
    char errbuf[100];
    //We open a device in order to capture packets
    if(device == NULL){
        exit(1);
    }

    // pcap_open_offline() is used to obtain a packet capture descriptor to look at packets from a given .pcap file
    // errbuf is used to return error or warning text
    pcap_t * capture = pcap_open_offline(device, errbuf);
    if (capture == NULL) {
        fprintf(stderr, "Error opening pcap file for capturing packets: %s\n", errbuf);
        exit(1);
    }

    // Get desired filter
    int destport;

    if(string_filter !=  NULL){  
        if (sscanf(string_filter, "port %d", &destport) == 1) {
            // The value was successfully extracted
            printf("Port number: %d\n", destport);
        }
        else {
            // Extraction failed, handle the error
            fprintf(stderr,"Error extracting port number.\n");
            exit(1);
        }
    }
    else{
        destport = 0;
    }
    // Set a callback function to process each packet
    pcap_loop(capture, 0, packet_handler_offline, (unsigned char*)&destport);

    // Close the pcap capture
    pcap_close(capture);
    printStatistics();
}

/******** Prints Help Message For The User *****/
void usage(void){
    printf(
        "\n"
        "usage:\n"
        "\t./pcap_ex \n"
        "Options:\n"
        "-i <interface name>, Select the network interface name (e.g., eth0)\n"
        "-r <capture file name>, Packet capture file name (e.g., test.pcap)\n"
        "-f <filter>, Filter expression in string format (e.g., port 8080)\n"
        "-h, Help message\n\n");

    exit(1);
}

/*****************************************************************/
// function to be called when the user presses control + c
void handle_program_exit(){

    // printf("\nCtrl+C pressed. Cleaning up...\n");    
    // Print statistics
    printStatistics();

    // Optionally, re-enable the default behavior for control+C 
    signal(SIGINT, SIG_DFL);

    // Trigger the interrupt again to exit the program
    raise(SIGINT);

}

/******************************************************************************/
int main(int argc, char *argv[]) {

    // initialise the variables
    mpz_init(totalBytesTCP);
    mpz_init(totalBytesUDP);
    mpz_set_si(totalBytesTCP,0);
    mpz_set_si(totalBytesUDP,0);
 
    // calling the handle_program_exit function when the user presses control+c to terminate the program
    signal(SIGINT, handle_program_exit);
    
    char* interfaceName = NULL;
    char* packetCaptureFileName = NULL;
    char* filter = NULL;
    for (int i = 1; i < argc; i++){
        char *arg = argv[i];

        if (strcmp(arg, "-h") == 0){
            usage();
        }
        else if (strcmp(arg, "-i") == 0){
            i++;
            interfaceName = (char *)malloc(strlen(argv[i] + 1));
            strcpy(interfaceName, argv[i]);
            printf("interfaceName = %s \n",interfaceName);
        }
        else if (strcmp(arg, "-r") == 0){
            i++;
            packetCaptureFileName = (char *)malloc(strlen(argv[i] + 1));
            strcpy(packetCaptureFileName, argv[i]);
            printf("packetCaptureFileName: %s \n",packetCaptureFileName);
        }
        else if (strcmp(arg, "-f") == 0){
            i++;
            filter = (char *)malloc(strlen(argv[i] + 1));
            strcpy(filter, argv[i]);
            printf("filter: %s \n",filter);
        }
        else{
            usage();
        }
    }

    // call the proper function
    if(interfaceName != NULL){
        // call function for online capture
        onlinePacketMonitoring(interfaceName,filter);             
    }
    else if (packetCaptureFileName != NULL){
        // call function for pcap reading
        offlinePacketMonitoring(packetCaptureFileName,filter);
        
    }
    else {
        fprintf(stderr, "Invalid");
        fflush(stdout);
        exit(1);
    }

    // clear the mpz_t 
    mpz_clear(totalBytesTCP);
    mpz_clear(totalBytesUDP);

    return 0;
}


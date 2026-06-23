#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <ctype.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));
    int ip_header_len = ip->iph_ihl * 4;
    
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;
    int ip_total_len = ntohs(ip->iph_len);
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;
    const u_char *payload =
        packet
        + sizeof(struct ethheader)
        + ip_header_len
        + tcp_header_len;
    
    // ether_ntoa : convert network byte's address to ASCII
    // ehter_ntoa(const struct ether_addr *__addr)
    printf("MAC src : %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));   
    printf("MAC dst : %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost)); 

    printf("IP src : %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("IP dst : %s\n", inet_ntoa(ip->iph_destip));    

    printf("TCP src port : %u\n", ntohs(tcp->tcp_sport));   
    printf("TCP dst port : %u\n", ntohs(tcp->tcp_dport));  

    if (payload_len > 0) {
        printf("   Payload:\n");

        for (int i = 0; i < payload_len; i++) {
            if (isprint(payload[i])) {
                printf("%c", payload[i]);
            } else {
                printf(".");
            }
        }

        printf("\n");
    }

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main(){
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net = 0;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
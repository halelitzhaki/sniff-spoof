#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    FILE * file = fopen("322989674 213562069.txt", "a+");
    struct ip *ip_header = (struct ip*)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));
    struct apphdr *app_header = (struct apphdr*)(packet + 14 + (ip_header->ip_hl *4));
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    
    fprintf(file, "{ source_ip: %s, dest_ip: %s\n", source_ip, dest_ip);
    fprintf(file, "  source_port: %d, dest_port: %d\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
    fprintf(file, "  timestamp: %ld, total_length: %d\n", header->ts.tv_sec, header->len);

    fprintf(file, " data : ");
    for (int i = 0; i < header->len; i++) {
        fprintf(file, "%02x ", packet[i]);
    }
    fprintf(file, " }\n\n");

    fclose(file);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    FILE * file = fopen("322989674 213562069.txt", "w");
    fclose(file);
    char filter_exp[] = "tcp";
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device lo: %s\n", errbuf);
	    return(2);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	    return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	    return(2);
    }

    pcap_loop(handle, -1, process_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}

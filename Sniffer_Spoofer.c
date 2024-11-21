#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/sockios.h>

struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};

struct icmpheader
{
    unsigned char icmp_type;        // ICMP message type
    unsigned char icmp_code;        // Error code
    unsigned short int icmp_chksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id;     // Used for identifying request
    unsigned short int icmp_seq;    // Sequence number
};

unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf, nleft = length, sum = 0;
    unsigned short temp = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    socklen_t len = sizeof(dest_info);
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));

    close(sock);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + 14);
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN], buffer[1500];

    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    memset(buffer, 0, 1500);

    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->icmp_type = 0; // ICMP Type: 8 is request, 0 is reply.

    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

    struct ipheader *ip = (struct ipheader *)buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr(dest_ip);
    ip->iph_destip.s_addr = inet_addr(source_ip);
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    send_raw_ip_packet(ip);
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE], filter_exp[] = "icmp and icmp[0] = 8";
    const char *device = "br-c335e7abde0e";
    pcap_t *handle;
    struct bpf_program fp;

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device lo: %s\n", errbuf);
        return (2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    pcap_loop(handle, -1, process_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
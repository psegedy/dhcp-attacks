/*
 * File: dhcp.h
 * Date: 21.4.2018
 * Name: DHCP Attacks, PDS project
 * Author: Patrik Segedy <xseged00@vutbr.cz>
 * Description: DHCP structure
 */

#ifndef __DHCP_H_
#define __DHCP_H_

#include <cstdint>
#include <cstdlib>


#define SERVER_PORT 67 // default server port
#define CLIENT_PORT 68  // default client port

#define OPTIONS_LENGTH 312
#define BROADCAST_BIT 32768

// DHCP message types
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7

// BOOTP
#define BOOTREQUEST 1
#define BOOTREPLY 2

// DHCP option magic cookie
#define MAGIC_COOKIE 0x63825363

// Packet length
#define PKT_LEN 8192


typedef struct dhcp_packet
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    u_char chaddr[16];
    u_char sname[64];
    u_char file[128];
    uint32_t cookie;
    u_char options[OPTIONS_LENGTH-6];
} __attribute__ ((packed)) dhcp_packet;

#endif

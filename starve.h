/*
 * File: starve.h
 * Date: 21.4.2018
 * Name: DHCP Starvation, PDS project
 * Author: Patrik Segedy <xseged00@vutbr.cz>
 * Description: DHCP Starvation
 */

#ifndef __STARVE_H_
#define __STARVE_H_

#include <iostream>

#include <csignal>
#include <cstring>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>


void handleSignal(int signal);
void gen_mac(uint8_t (&mac)[6]);

#endif // STARVE_H_

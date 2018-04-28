/*
 * File: starve.h
 * Date: 28.4.2018
 * Name: DHCP Starvation, PDS project
 * Author: Patrik Segedy <xseged00@vutbr.cz>
 * Description: DHCP Starvation
 */

#ifndef __CHECKSUM_H_
#define __CHECKSUM_H_

#include <sys/types.h>

unsigned short in_cksum(unsigned short *addr, int len);

#endif // __CHECKSUM_H_

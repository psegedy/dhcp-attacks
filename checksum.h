#ifndef __CHECKSUM_H_
#define __CHECKSUM_H_

#include <sys/types.h>

unsigned short in_cksum(unsigned short *addr, int len);

#endif // __CHECKSUM_H_

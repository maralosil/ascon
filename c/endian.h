/*
 * endian.h
 *
 *  Created on: 26 de jun. de 2022
 *      Author: marcelo
 */

#ifndef ENDIAN_H
#define ENDIAN_H

#include <inttypes.h>

# if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t force_big_endian(uint64_t x)
{
	return (0x00000000000000ffull & x) << 56
			| (0x000000000000ff00ull & x) << 40
			| (0x0000000000ff0000ull & x) << 24
			| (0x00000000ff000000ull & x) << 8
			| (0x000000ff00000000ull & x) >> 8
			| (0x0000ff0000000000ull & x) >> 24
			| (0x00ff000000000000ull & x) >> 40
			| (0xff00000000000000ull & x) >> 56;
}
#else
#define force_big_endian(x)	(x)
#endif

#endif /* ENDIAN_H */

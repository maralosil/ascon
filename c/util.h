/*
 * util.h
 *
 *  Created on: 26 de jun. de 2022
 *      Author: marcelo
 */

#ifndef UTIL_H
#define UTIL_H

#include "endian.h"

static inline uint64_t mask(uint8_t n)
{
	return ~0ull >> (64 - 8 * n);
}

static inline uint64_t load(const uint8_t *p, uint8_t n)
{
	uint64_t x = *(uint64_t*) p & mask(n);
	return force_big_endian(x);
}

static inline void store(uint8_t *c, uint64_t x, int n)
{
	*(uint64_t*) c &= ~mask(n);
	*(uint64_t*) c |= force_big_endian(x);
}

static inline uint64_t clear(uint64_t x, int n)
{
	uint64_t mask = ~0ull >> (8 * n);
	return x & mask;
}

static inline int notzero(uint64_t a, uint64_t b)
{
	uint64_t result = a | b;

	result |= result >> 32;
	result |= result >> 16;
	result |= result >> 8;

	return ((((int) (result & 0xff) - 1) >> 8) & 1) - 1;
}

static inline uint64_t pad(int n)
{
	return 0x80ull << (56 - 8 * n);
}

static inline uint64_t rotr(uint64_t x, uint8_t n)
{
	return x >> n | x << (64 - n);
}

#endif /* UTIL_H */

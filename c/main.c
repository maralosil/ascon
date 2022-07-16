/*
 * main.c
 *
 *  Created on: 7 de jun. de 2022
 *      Author: marcelo
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "ascon.h"

int main(void)
{
	const uint8_t k[] = "Keep it secret.";
	const uint8_t n[] = "Only used once.";
	const uint8_t p[] = "Your voice is always heard. — NSA";
	const uint8_t ad[] = "The enemy knows the system. — Claude Shannon";
	uint8_t c[sizeof(p) + 16];
	uint8_t q[sizeof(p)];
	uint32_t clen, qlen;
	struct ascon_aead as;
	int err;

	ascon_aead_setup(&as, ASCON128a);

	ascon_aead_encrypt(&as, k, n, ad, sizeof(ad), p, sizeof(p), c, &clen);
	err = ascon_aead_decrypt(&as, k, n, ad, sizeof(ad), c, clen, q, &qlen);
	if (err) {
		fprintf(stderr, "Failed to decrypt\n");
		return 1;
	}

	if (qlen != sizeof(p)) {
		fprintf(stderr, "Bad plaintext length\n");
		return 1;
	}

	if (memcmp(p, q, qlen)) {
		fprintf(stderr, "Plaintext mismatch\n");
		return 1;
	}

	printf("Success\n");

	return 0;
}

/*
 * ascon.c
 *
 *  Created on: 7 de jun. de 2022
 *      Author: marcelo
 */

#include "ascon.h"
#include "util.h"

#define ASCON128_IV	0x80400c0600000000ull
#define ASCON128a_IV	0x80800c0800000000ull

#define ASCON_HASH_IV	0x00400c0000000100ull
#define ASCON_XOF_IV	0x00400c0000000000ull

/**
 * struct key - stores the key in words of 64 bits
 *
 * @k: array containing key data in two words of 64 bits.
 */
struct key {
	uint64_t k[2];
};

/**
 * struct state - represents the 320-bit state of ascon
 *
 * @x: array containing the five 64-bit registers of the state
 */
struct state {
	uint64_t x[5];
};

/**
 * ascon_permutate - performs the permutation
 *
 * @s: the state
 * @nr: the number of rounds
 *
 * Performs the main permutation for ascon algorithms using the given
 * number of rounds.
 */
static void ascon_permutate(struct state *s, uint8_t nr)
{
	uint64_t t[5];

	for (uint8_t i = 12 - nr; i < 12; ++i) {
		// constant addition layer
		s->x[2] ^= (((uint64_t) (0xf) - i) << 4) | i;

		// substitution layer (SBox)
		s->x[0] ^= s->x[4];
		s->x[4] ^= s->x[3];
		s->x[2] ^= s->x[1];
		t[0] = s->x[0];
		t[1] = s->x[1];
		t[2] = s->x[2];
		t[3] = s->x[3];
		t[4] = s->x[4];
		t[0] = ~t[0];
		t[1] = ~t[1];
		t[2] = ~t[2];
		t[3] = ~t[3];
		t[4] = ~t[4];
		t[0] &= s->x[1];
		t[1] &= s->x[2];
		t[2] &= s->x[3];
		t[3] &= s->x[4];
		t[4] &= s->x[0];
		s->x[0] ^= t[1];
		s->x[1] ^= t[2];
		s->x[2] ^= t[3];
		s->x[3] ^= t[4];
		s->x[4] ^= t[0];
		s->x[1] ^= s->x[0];
		s->x[0] ^= s->x[4];
		s->x[3] ^= s->x[2];
		s->x[2] = ~s->x[2];

		// linear diffusion layer
		s->x[0] ^= rotr(s->x[0], 19) ^ rotr(s->x[0], 28);
		s->x[1] ^= rotr(s->x[1], 61) ^ rotr(s->x[1], 39);
		s->x[2] ^= rotr(s->x[2], 1) ^ rotr(s->x[2], 6);
		s->x[3] ^= rotr(s->x[3], 10) ^ rotr(s->x[3], 17);
		s->x[4] ^= rotr(s->x[4], 7) ^ rotr(s->x[4], 41);
	}
}

/**
 * ascon_aead_init - initializes the ascon aead state
 *
 * @as:  [in] the ascon aead
 * @key: [in] the key in two words of 64 bits
 * @s:   [in] the state
 * @k:   [in] the key
 * @n:   [in] the nonce
 *
 * Initializes the ascon aead state.
 */
static void ascon_aead_init(struct ascon_aead *as, struct key *key,
			    struct state *s, const uint8_t *k,
			    const uint8_t *n)
{
	key->k[0] = load(k, 8);
	key->k[1] = load(k + 8, 8);
	s->x[0] = as->iv;
	s->x[1] = key->k[0];
	s->x[2] = key->k[1];
	s->x[3] = load(n, 8);
	s->x[4] = load(n + 8, 8);
	ascon_permutate(s, as->a);
	s->x[3] ^= key->k[0];
	s->x[4] ^= key->k[1];
}

/**
 * ascon_aead_proc_adata - process the associated data
 *
 * @as:    [in] the ascon aead
 * @s:     [in] the state
 * @ad:    [in] the associated data
 * @adlen: [in] the associated data length
 *
 * Process the associated data.
 */
static void ascon_aead_proc_adata(struct ascon_aead *as, struct state *s,
				  const uint8_t *ad, uint64_t adlen)
{
	if (adlen == 0)
		return;

	while (adlen >= as->r) {
		s->x[0] ^= load(ad, 8);

		if (as->r == 16)
			s->x[1] ^= load(ad + 8, 8);

		ascon_permutate(s, as->b);
		ad += as->r;
		adlen -= as->r;
	}

	uint64_t *x = &s->x[0];
	if (as->r == 16 && adlen >= 8) {
		s->x[0] ^= load(ad, 8);
		x = &s->x[1];
		ad += 8;
		adlen -= 8;
	}

	*x ^= pad(adlen);

	if (adlen > 0)
		*x ^= load(ad, adlen);

	ascon_permutate(s, as->b);

// domain separation
	s->x[4] ^= 1;
}

/**
 * ascon_aead_proc_ptext - process the plaintext
 *
 * @as:   [in] the ascon aead
 * @s:    [in] the state
 * @p:    [in] the plaintext
 * @plen: [in] the plaintext length
 * @c:    [out] the ciphertext
 *
 * Process the plaintext.
 */
static void ascon_aead_proc_ptext(struct ascon_aead *as, struct state *s,
				  const uint8_t *p, uint32_t plen, uint8_t *c)
{
	while (plen >= as->r) {
		s->x[0] ^= load(p, 8);
		store(c, s->x[0], 8);

		if (as->r == 16) {
			s->x[1] ^= load(p + 8, 8);
			store(c + 8, s->x[1], 8);
		}

		ascon_permutate(s, as->b);
		p += as->r;
		plen -= as->r;
		c += as->r;
	}

	uint64_t *x = &s->x[0];
	if (as->r == 16 && plen >= 8) {
		s->x[0] ^= load(p, 8);
		store(c, s->x[0], 8);
		x = &s->x[1];
		p += 8;
		plen -= 8;
		c += 8;
	}

	*x ^= pad(plen);

	if (plen > 0) {
		*x ^= load(p, plen);
		store(c, *x, plen);
	}
}

/**
 * ascon_aead_proc_ctext - process the ciphertext
 *
 * @as:   [in] the ascon aead
 * @s:    [in] the state
 * @c:    [in] the ciphertext
 * @clen: [in] the ciphertext length
 * @p:    [out] the plaintext
 *
 * Process the ciphertext.
 */
static void ascon_aead_proc_ctext(struct ascon_aead *as, struct state *s,
				  const uint8_t *c, uint32_t clen, uint8_t *p)
{
	uint64_t t;

	while (clen >= as->r) {
		t = load(c, 8);
		s->x[0] ^= t;
		store(p, s->x[0], 8);
		s->x[0] = t;

		if (as->r == 16) {
			t = load(c + 8, 8);
			s->x[1] ^= t;
			store(p + 8, s->x[1], 8);
			s->x[1] = t;
		}

		ascon_permutate(s, as->b);
		c += as->r;
		clen -= as->r;
		p += as->r;
	}

	uint64_t *x = &s->x[0];
	if (as->r == 16 && clen >= 8) {
		t = load(c, 8);
		s->x[0] ^= t;
		store(p, s->x[0], 8);
		s->x[0] = t;
		x = &s->x[1];
		c += 8;
		clen -= 8;
		p += 8;
	}

	*x ^= pad(clen);

	if (clen > 0) {
		t = load(c, clen);
		*x ^= t;
		store(p, *x, clen);
		// clear
		*x = clear(*x, clen);
		*x ^= t;

	}
}

/**
 * ascon_aead_final - finalizes the ascon aead state
 *
 * @as:   [in] the ascon aead
 * @key:  [in] the key in two words of 64 bits
 * @s:    [in] the state
 *
 * Finalizes the ascon aead state
 */
static void ascon_aead_final(struct ascon_aead *as, struct key *key,
			     struct state *s)
{
	if (as->r == 16) {
		s->x[2] ^= key->k[0];
		s->x[3] ^= key->k[1];
	} else {
		s->x[1] ^= key->k[0];
		s->x[2] ^= key->k[1];
	}

	ascon_permutate(s, as->a);
	s->x[3] ^= key->k[0];
	s->x[4] ^= key->k[1];
}

static void ascon_aead_prep(struct ascon_aead *as, uint8_t r,
			    uint8_t a, uint8_t b, uint64_t iv)
{
	as->r = r;
	as->a = a;
	as->b = b;
	as->iv = iv;
}

void ascon_aead_setup(struct ascon_aead *as, enum ascon_aead_variant v)
{
	switch (v) {
	case ASCON128:
		ascon_aead_prep(as, 8, 12, 6, ASCON128_IV);
		break;
	case ASCON128a:
		ascon_aead_prep(as, 16, 12, 8, ASCON128a_IV);
		break;
	default:
		ascon_aead_prep(as, 8, 12, 6, ASCON128_IV);
		break;
	}
}

static void ascon_hash_prep(struct ascon_hash *as, uint8_t r, uint8_t a,
			    uint64_t iv)
{
	as->r = r;
	as->a = a;
	as->iv = iv;
}

void ascon_hash_setup(struct ascon_hash *as, enum ascon_hash_variant v)
{
	switch (v) {
	case ASCON_HASH:
		ascon_hash_prep(as, 8, 12, ASCON_HASH_IV);
		break;
	case ASCON_XOF:
		ascon_hash_prep(as, 8, 12, ASCON_XOF_IV);
		break;
	default:
		ascon_hash_prep(as, 8, 12, ASCON_XOF_IV);
		break;
	}
}

void ascon_aead_encrypt(struct ascon_aead *as, const uint8_t *k,
			const uint8_t *n, const uint8_t *ad, uint32_t adlen,
			const uint8_t *p, uint32_t plen, uint8_t *c,
			uint32_t *clen)
{
	struct key key;
	struct state s;

	*clen = plen + ASCON_TAG_SIZE;

	ascon_aead_init(as, &key, &s, k, n);
	ascon_aead_proc_adata(as, &s, ad, adlen);
	ascon_aead_proc_ptext(as, &s, p, plen, c);
	ascon_aead_final(as, &key, &s);

	store(c + plen, s.x[3], 8);
	store(c + plen + 8, s.x[4], 8);
}

int ascon_aead_decrypt(struct ascon_aead *as, const uint8_t *k,
			const uint8_t *n, const uint8_t *ad, uint32_t adlen,
			const uint8_t *c, uint32_t clen, uint8_t *p,
			uint32_t *plen)
{
	struct key key;
	struct state s;

	*plen = clen - ASCON_TAG_SIZE;
	clen = *plen;

	ascon_aead_init(as, &key, &s, k, n);
	ascon_aead_proc_adata(as, &s, ad, adlen);
	ascon_aead_proc_ctext(as, &s, c, clen, p);
	ascon_aead_final(as, &key, &s);

	s.x[3] ^= load(c + clen, 8);
	s.x[4] ^= load(c + clen + 8, 8);

	return notzero(s.x[3], s.x[4]);
}

static void ascon_hash_init(struct ascon_hash *as, struct state *s)
{
	int i;

	s->x[0] = as->iv;

	for (i = 1; i < 5; i++)
		s->x[i] = 0;

	ascon_permutate(s, as->a);
}

static void ascon_hash_absorb(struct ascon_hash *as, struct state *s,
				const uint8_t *m, uint32_t mlen)
{
	while (mlen >= as->r) {
		s->x[0] ^= load(m, 8);

		if (as->r == 16)
			s->x[1] ^= load(m + 8, 8);

		ascon_permutate(s, as->a);
		m += as->r;
		mlen -= as->r;
	}

	uint64_t *x = &s->x[0];
	if (as->r == 16 && mlen >= 8) {
		s->x[0] ^= load(m, 8);
		x = &s->x[1];
		m += 8;
		mlen -= 8;
	}

	*x ^= pad(mlen);

	if (mlen > 0)
		*x ^= load(m, mlen);

	ascon_permutate(s, as->a);
}

static void ascon_hash_squeeze(struct ascon_hash *as, struct state *s,
				uint8_t *out, uint32_t outlen)
{
	while (outlen >= as->r) {
		store(out, s->x[0], 8);

		if (as->r == 16)
			store(out + 8, s->x[1], 8);

		ascon_permutate(s, as->a);
		out += as->r;
		outlen -= as->r;
	}

	uint64_t *x = &s->x[0];
	if (as->r == 16 && outlen >= 8) {
		store(out, s->x[0], 8);
		x = &s->x[1];
		out += 8;
		outlen -= 8;
	}

	if (outlen > 0)
		store(out, *x, outlen);
}

void ascon_hash_output(struct ascon_hash *as, const uint8_t *m, uint32_t mlen,
			uint8_t *out)
{
	ascon_xof_output(as, m, mlen, out, 32);
}

void ascon_xof_output(struct ascon_hash *as, const uint8_t *m, uint32_t mlen,
			uint8_t *out, uint32_t outlen)
{
	struct state s;

	ascon_hash_init(as, &s);
	ascon_hash_absorb(as, &s, m, mlen);
	ascon_hash_squeeze(as, &s, out, outlen);
}

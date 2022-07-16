/*
 * ascon.h
 *
 *  Created on: 7 de jun. de 2022
 *      Author: marcelo
 */

#ifndef ASCON_H
#define ASCON_H

#include <inttypes.h>

/**
 * enum - the ascon aead variant
 */
enum ascon_aead_variant {
	ASCON128,
	ASCON128a
};

/**
 * enum - the ascon variant
 */
enum ascon_hash_variant {
	ASCON_HASH,
	ASCON_XOF
};

/**
 * struct ascon_aead - the ascon aead instance
 *
 * @r: the rate in bytes
 * @a: permutation rounds a
 * @b: permutation rounds b
 * @iv: initialization vector
 *
 * Represents the ascon aead with its security parameters.
 */
struct ascon_aead {
	uint8_t r;
	uint8_t a;
	uint8_t b;
	uint64_t iv;
};

/**
 * struct ascon_hash - the ascon hash instance
 *
 * @r: the rate in bytes
 * @a: permutation rounds a
 * @iv: initialization vector
 *
 * Represents the ascon hash with its security parameters.
 */
struct ascon_hash {
	uint8_t r;
	uint8_t a;
	uint64_t iv;
};

/**
 * ascon_aead_setup - initializes the ascon aead
 *
 * @as: [out] the initialized ascon aead
 * @v:  [in] the ascon aead variant
 *
 * Initializes the ascon aead for the specified variant.
 */
void ascon_aead_setup(struct ascon_aead *as, enum ascon_aead_variant v);

/**
 * ascon_hash_setup - initializes the ascon hash
 *
 * @as: [out] the initialized ascon hash
 * @v:  [in] the ascon hash variant
 *
 * Initializes the ascon hash for the specified variant.
 */
void ascon_hash_setup(struct ascon_hash *as, enum ascon_hash_variant v);

/**
 * ascon_aead_encrypt - authenticated encryption with associate data
 *
 * @as:    [in] the ascon aead instance
 * @k:     [in] the key
 * @n:     [in] the nonce
 * @ad:    [in] the associated data
 * @adlen: [in] the associate data length
 * @p:     [in] the plaintext
 * @plen:  [in] the plaintext length
 * @c:     [out] the ciphertext
 * @clen:  [out] the ciphertext length
 *
 * Performs the authenticated encryption for the specified plaintext and
 * associated data.
 */
void ascon_aead_encrypt(struct ascon_aead *as, const uint8_t *k,
			const uint8_t *n, const uint8_t *ad, uint32_t adlen,
			const uint8_t *p, uint32_t plen, uint8_t *c,
			uint32_t *clen);

/**
 * ascon_aead_decrypt - verified decryption with associate data
 *
 * @as:    [in] the ascon aead instance
 * @k:     [in] the key
 * @n:     [in] the nonce
 * @ad:    [in] the associated data
 * @adlen: [in] the associate data length
 * @c:     [in] the ciphertext
 * @clen:  [in] the ciphertext length
 * @p:     [out] the plaintext
 * @plen:  [out] the plaintext length
 *
 * Performs the verified decryption for the specified ciphertext and
 * associated data.
 *
 * Returns 0 if the verification succeeds, otherwise returns 1.
 */
int ascon_aead_decrypt(struct ascon_aead *as, const uint8_t *k,
			const uint8_t *n, const uint8_t *ad, uint32_t adlen,
			const uint8_t *c, uint32_t clen, uint8_t *p,
			uint32_t *plen);

/**
 * ascon_hash_output - outputs the hash value with a length of 32 bytes
 *
 * @as:     [in] the ascon instance
 * @m:      [in] the message
 * @mlen:   [in] the message length
 * @out:    [out] the output
 *
 * Outputs the hash value with a length of 32 bytes (256 bits) for the input
 * message.
 */
void ascon_hash_output(struct ascon_hash *as, const uint8_t *m, uint32_t mlen,
			uint8_t *out);

/**
 * ascon_xof_output - outputs the hash value with the specified output length
 *
 * @as:     [in] the ascon instance
 * @m:      [in] the message
 * @mlen:   [in] the message length
 * @out:    [out] the output
 * @outlen: [in] the output length
 *
 * Outputs the hash value with the specified output length for the input
 * message.
 */
void ascon_xof_output(struct ascon_hash *as, const uint8_t *m, uint32_t mlen,
			uint8_t *out, uint32_t outlen);

#endif /* ASCON_H */

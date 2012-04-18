/* Reference implementation of Moeller 2004, "A Public-Key Encryption
   Scheme with Pseudo-Random Ciphertexts" (key encapsulation only).
   Written and placed in the public domain by Zack Weinberg, 2012. */

#ifndef _MREF_OPENSSL_H_
#define _MREF_OPENSSL_H_

#include <stddef.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

typedef struct MKEMParams
{
  BN_CTX *ctx;

  const BIGNUM *m;
  const BIGNUM *b;
  const BIGNUM *a0;
  const BIGNUM *a1;
  const BIGNUM *p0;
  const BIGNUM *p1;
  const BIGNUM *n0;
  const BIGNUM *n1;
  const BIGNUM *maxu;

  const EC_GROUP *c0;
  const EC_GROUP *c1;

  const EC_POINT *g0;
  const EC_POINT *g1;

  size_t  msgsize;
  uint8_t padmask;
} MKEMParams;

int MKEMParams_init(MKEMParams *params);
void MKEMParams_teardown(MKEMParams *params);

typedef struct MKEM
{
  const MKEMParams *params;
  const BIGNUM *s0;
  const BIGNUM *s1;
  const EC_POINT *p0;
  const EC_POINT *p1;
} MKEM;

void MKEM_teardown(MKEM *kp);

/* Generate a brand new keypair from randomness. */
int MKEM_init_random(MKEM *kp, const MKEMParams *params);

/* Load a secret key expressed as two integers (s0, s1), and
   regenerate the public key from it. Note: the BIGNUM-taking variant
   assumes ownership of the BIGNUMs.  */
int MKEM_init_sk_bignum(MKEM *kp, const MKEMParams *params,
                        BIGNUM *s0, BIGNUM *s1);
int MKEM_init_sk_vec(MKEM *kp, const MKEMParams *params,
                     const uint8_t *s0, size_t s0l,
                     const uint8_t *s1, size_t s1l);

/* Load a public key expressed as two elliptic curve points (p0, p1).
   Since the secret key is not available, MKEM_export_secret_key and
   MKEM_decode_message will fail if called on this MKEM. Note: the
   EC_POINT-taking variant assumes ownership of the EC_POINTs. */
int MKEM_init_pk_point(MKEM *kp, const MKEMParams *params,
                       EC_POINT *p0, EC_POINT *p1);
int MKEM_init_pk_vec(MKEM *kp,
                     const MKEMParams *params,
                     const uint8_t *p0, size_t p0l,
                     const uint8_t *p1, size_t p1l);

/* Export the public key as a pair of points. For _pt, the EC_POINTs
   must already have been initialized. For _vec, the byte buffers must
   each point to at least kp->params->msgsize+1 bytes of storage. */
int MKEM_export_public_key_pt(const MKEM *kp, EC_POINT *p0, EC_POINT *p1);
int MKEM_export_public_key_vec(const MKEM *kp, uint8_t *p1, uint8_t *p2);

/* Export the secret key as a pair of integers.  For _bn, the BIGNUMs
   must already have been initialized.  For _vec, the byte buffers must
   each point to at least kp->params->msgsize bytes of storage. */
int MKEM_export_secret_key_bn(const MKEM *kp, BIGNUM *s0, BIGNUM *s1);
int MKEM_export_secret_key_vec(const MKEM *kp, uint8_t *s0, uint8_t *s1);

/* Generate secret material K and encrypted message kk from randomness.
   This does NOT carry out key derivation; the "secret" output is what
   the paper describes as $\mathfrak{k} || encode(x_R)$, not KDF of that.
   The 'message' argument must point to at least kp->params->msgsize
   bytes of storage, and the 'secret' argument must point to twice
   that much storage.  */
int MKEM_generate_message(const MKEM *kp, uint8_t *secret, uint8_t *message);

/* Same, but work from a preselected integer 'u', which must be in the
   closed interval [1, kp->params->maxu], and an extra byte's worth of
   random bits for padding.

   This is exposed only for the sake of known-answer tests.  Use of
   non-random 'u' or 'pad' invalidates system properties, as does
   reuse of either value. */
int MKEM_generate_message_u(const MKEM *kp, const BIGNUM *u, uint8_t pad,
                            uint8_t *secret, uint8_t *message);

/* Decode an encrypted message.  As with MKEM_generate_message, the
   result is NOT run through a KDF. */
int MKEM_decode_message(const MKEM *kp, uint8_t *secret,
                        const uint8_t *message);

#endif

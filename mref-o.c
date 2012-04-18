/* Reference implementation of Moeller 2004, "A Public-Key Encryption
   Scheme with Pseudo-Random Ciphertexts" (key encapsulation only).
   Written and placed in the public domain by Zack Weinberg, 2012. */

#include "mref-o.h"
#include "curves.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#define FAILZ(expr) if ((expr) == 0) goto fail;

int
MKEMParams_init(MKEMParams *params)
{
  const mk_curve_params *p = &mk_curves[MK_CURVE_163_0];
  BIGNUM *maxu = 0;
  size_t bitsize, bytesize, bitcap, k;
  uint8_t mask;

  memset(params, 0, sizeof(MKEMParams));

  FAILZ(params->ctx = BN_CTX_new());

  FAILZ(params->m  = BN_bin2bn(p->m,  p->L_m,  0));
  FAILZ(params->b  = BN_bin2bn(p->b,  p->L_b,  0));
  FAILZ(params->a0 = BN_new()); FAILZ(BN_zero((BIGNUM *)params->a0));
  FAILZ(params->a1 = BN_value_one());
  FAILZ(params->p0 = BN_bin2bn(p->p0, p->L_p0, 0));
  FAILZ(params->p1 = BN_bin2bn(p->p1, p->L_p1, 0));
  FAILZ(params->n0 = BN_bin2bn(p->n0, p->L_n0, 0));
  FAILZ(params->n1 = BN_bin2bn(p->n1, p->L_n1, 0));

  FAILZ(params->c0 = EC_GROUP_new_curve_GF2m(params->m, params->a0, params->b,
                                             params->ctx));
  FAILZ(params->c1 = EC_GROUP_new_curve_GF2m(params->m, params->a1, params->b,
                                             params->ctx));

  FAILZ(params->g0 = EC_POINT_new(params->c0));
  FAILZ(EC_POINT_oct2point(params->c0, (EC_POINT *)params->g0, p->g0, p->L_g0,
                           params->ctx));
  FAILZ(params->g1 = EC_POINT_new(params->c1));
  FAILZ(EC_POINT_oct2point(params->c1, (EC_POINT *)params->g1, p->g1, p->L_g1,
                           params->ctx));

  /* Calculate the upper limit for the random integer U input to
     MKEM_generate_message_u.

     The paper calls for us to choose between curve 0 and curve 1 with
     probability proportional to the number of points on that curve, and
     then choose a random integer in the range 0 < u < n{curve}.  The
     easiest way to do this accurately is to choose a random integer in the
     range [1, n0 + n1 - 2].  If it is less than n0, MKEM_generate_message_u
     will use it unmodified with curve 0.  If it is greater than or equal
     to n0, MKEM_generate_message_u will subtract n0-1, leaving a number in
     the range [1, n1-1], and use that with curve 1. */

  FAILZ(maxu = BN_dup(params->n0));
  FAILZ(BN_add(maxu, maxu, params->n1));
  FAILZ(BN_sub(maxu, maxu, BN_value_one()));
  FAILZ(BN_sub(maxu, maxu, BN_value_one()));
  params->maxu = maxu; maxu = 0;

  /* Calculate the maximum size of a message and the padding mask applied
     to the high byte of each message.  See MKEM_generate_message_u for
     further exposition. */
  bitsize = EC_GROUP_get_degree(params->c0);
  if ((size_t)EC_GROUP_get_degree(params->c1) != bitsize)
    goto fail;

  bytesize = (bitsize + 7) / 8;
  bitcap = bytesize * 8;
  k = bitcap - bitsize;
  mask = ~((1 << (8 - k)) - 1);
  params->msgsize = bytesize;
  params->padmask = mask;

  return 0;

 fail:
  if (maxu) BN_free(maxu);
  MKEMParams_teardown(params);
  return -1;
}

void
MKEMParams_teardown(MKEMParams *params)
{
  /* none of the values in an MKEMParams are secret, so don't bother
     clearing them */
  if (params->ctx)  BN_CTX_free(params->ctx);

  if (params->m)    BN_free((BIGNUM *)params->m);
  if (params->b)    BN_free((BIGNUM *)params->b);
  if (params->a0)   BN_free((BIGNUM *)params->a0);
  /* a1 is the static BN_value_one() constant and should not be freed */
  if (params->p0)   BN_free((BIGNUM *)params->p0);
  if (params->p1)   BN_free((BIGNUM *)params->p1);
  if (params->n0)   BN_free((BIGNUM *)params->n0);
  if (params->n1)   BN_free((BIGNUM *)params->n1);
  if (params->maxu) BN_free((BIGNUM *)params->maxu);

  if (params->c0)   EC_GROUP_free((EC_GROUP *)params->c1);
  if (params->c1)   EC_GROUP_free((EC_GROUP *)params->c1);

  if (params->g0)   EC_POINT_free((EC_POINT *)params->g0);
  if (params->g1)   EC_POINT_free((EC_POINT *)params->g1);

  memset(params, 0, sizeof(MKEMParams));
}

void
MKEM_teardown(MKEM *kp)
{
  /* s0 and s1 are secret. p0 and p1 are not secret, but clear them
     anyway. */
  if (kp->s0) BN_clear_free((BIGNUM *)kp->s0);
  if (kp->s1) BN_clear_free((BIGNUM *)kp->s1);

  if (kp->p0) EC_POINT_clear_free((EC_POINT *)kp->p0);
  if (kp->p1) EC_POINT_clear_free((EC_POINT *)kp->p1);

  memset(kp, 0, sizeof(MKEM));
}

/* The secret integers s0 and s1 must be in the range 0 < s < n for
   some n, and must be relatively prime to that n.  We know a priori
   that n is of the form 2**k * p for some small integer k and prime
   p.  Therefore, it suffices to choose a random integer in the range
   [0, n/2), multiply by two and add one (enforcing oddness), and then
   reject values which are divisible by p.  */
static BIGNUM *
random_s(const BIGNUM *n, const BIGNUM *p, BN_CTX *c)
{
  BIGNUM h, m, *r;

  BN_init(&h);
  BN_init(&m);
  FAILZ(r = BN_new());
  FAILZ(BN_copy(&h, n));
  FAILZ(BN_rshift1(&h, &h));

  do {
    FAILZ(BN_rand_range(r, &h));
    FAILZ(BN_lshift1(r, r));
    FAILZ(BN_add(r, r, BN_value_one()));
    FAILZ(BN_nnmod(&m, r, p, c));
  } while (BN_is_zero(&m));

  BN_clear(&h);
  BN_clear(&m);
  return r;

 fail:
  BN_clear(&h);
  BN_clear(&m);
  if (r) BN_clear_free(r);
  return 0;
}

int
MKEM_init_sk_bignum(MKEM *kp, const MKEMParams *params,
                    BIGNUM *s0, BIGNUM *s1)
{
  /* set ->params, ->s0, ->s1, before checking any of them, to ensure that
     if any one of them is null, the other two are not leaked */
  kp->params = params;
  kp->s0 = s0;
  kp->s1 = s1;
  FAILZ(params); FAILZ(s0); FAILZ(s1);

  FAILZ(kp->p0 = EC_POINT_new(params->c0));
  FAILZ(kp->p1 = EC_POINT_new(params->c1));
  FAILZ(EC_POINT_mul(params->c0, (EC_POINT *)kp->p0,
                     0, params->g0, kp->s0, params->ctx));
  FAILZ(EC_POINT_mul(params->c1, (EC_POINT *)kp->p1,
                     0, params->g1, kp->s1, params->ctx));
  return 0;

 fail:
  MKEM_teardown(kp);
  return -1;
}

int
MKEM_init_sk_vec(MKEM *kp, const MKEMParams *params,
                 const uint8_t *s0, size_t s0l,
                 const uint8_t *s1, size_t s1l)
{
  return MKEM_init_sk_bignum(kp, params,
                             BN_bin2bn(s0, s0l, 0),
                             BN_bin2bn(s1, s1l, 0));
}

int
MKEM_init_random(MKEM *kp, const MKEMParams *params)
{
  return MKEM_init_sk_bignum(kp, params,
                             random_s(params->n0, params->p0, params->ctx),
                             random_s(params->n1, params->p1, params->ctx));
}

int
MKEM_init_pk_point(MKEM *kp, const MKEMParams *params,
                   EC_POINT *p0, EC_POINT *p1)
{
  kp->params = params;
  kp->s0 = 0;
  kp->s1 = 0;
  kp->p0 = p0;
  kp->p1 = p1;

  if (params && p0 && p1)
    return 0; /* success */
  MKEM_teardown(kp);
  return -1;
}

int
MKEM_init_pk_vec(MKEM *kp,
                 const MKEMParams *params,
                 const uint8_t *p0, size_t p0l,
                 const uint8_t *p1, size_t p1l)
{
  EC_POINT *pp0 = EC_POINT_new(params->c0);
  EC_POINT *pp1 = EC_POINT_new(params->c1);

  FAILZ(pp0); FAILZ(pp1);
  FAILZ(EC_POINT_oct2point(params->c0, pp0, p0, p0l, params->ctx));
  FAILZ(EC_POINT_oct2point(params->c1, pp1, p1, p1l, params->ctx));

  return MKEM_init_pk_point(kp, params, pp0, pp1);

 fail:
  if (pp0) EC_POINT_clear_free(pp0);
  if (pp1) EC_POINT_clear_free(pp1);
  return -1;
}

int
MKEM_export_public_key_pt(const MKEM *kp, EC_POINT *p0, EC_POINT *p1)
{
  return (EC_POINT_copy(p0, kp->p0) && EC_POINT_copy(p1, kp->p1)) ? 0 : -1;
}

int
MKEM_export_public_key_vec(const MKEM *kp, uint8_t *p0, uint8_t *p1)
{
  size_t vsize = kp->params->msgsize + 1;

  if (EC_POINT_point2oct(kp->params->c0, kp->p0, POINT_CONVERSION_COMPRESSED,
                         p0, vsize, kp->params->ctx) != vsize ||
      EC_POINT_point2oct(kp->params->c1, kp->p1, POINT_CONVERSION_COMPRESSED,
                         p1, vsize, kp->params->ctx) != vsize)
    return -1;
  return 0;
}

int
MKEM_export_secret_key_bn(const MKEM *kp, BIGNUM *s0, BIGNUM *s1)
{
  if (!s0 || !s1) return -1;

  return (BN_copy(s0, kp->s0) && BN_copy(s0, kp->s1)) ? 0 : -1;
}

/* Write the BIGNUM 'b' to 'to', padded at the high end so that the
   result occupies _exactly_ 'sz' bytes.  If 'b' requires more than 'sz'
   bytes it is an error. */
static size_t
bn2bin_padhi(const BIGNUM *b, uint8_t *to, size_t sz)
{
  size_t n = BN_num_bytes(b);
  if (n > sz)
    return 0;
  if (n < sz) {
    memset(to, 0, sz - n);
    to += sz - n;
  }
  return BN_bn2bin(b, to) + (sz - n);
}

int
MKEM_export_secret_key_vec(const MKEM *kp, uint8_t *s0, uint8_t *s1)
{
  if (!s0 || !s1) return -1;
  if (bn2bin_padhi(kp->s0, s0, kp->params->msgsize) != kp->params->msgsize ||
      bn2bin_padhi(kp->s1, s1, kp->params->msgsize) != kp->params->msgsize)
    return -1;
  return 0;
}

int
MKEM_generate_message(const MKEM *kp, uint8_t *secret, uint8_t *message)
{
  BIGNUM u;
  uint8_t pad;
  int rv = -1;
  BN_init(&u);
  if (BN_rand_range(&u, kp->params->maxu) &&
      BN_add(&u, &u, BN_value_one()) &&
      RAND_bytes(&pad, 1) &&
      !MKEM_generate_message_u(kp, &u, pad, secret, message))
    rv = 0;

  BN_clear(&u);
  return rv;
}

int
MKEM_generate_message_u(const MKEM *kp, const BIGNUM *uraw, uint8_t pad,
                        uint8_t *secret, uint8_t *message)
{
  BIGNUM u, x, y;
  int use_curve0 = (BN_cmp(uraw, kp->params->n0) < 0);
  const EC_GROUP *ca;
  const EC_POINT *ga;
  const EC_POINT *pa;
  EC_POINT *q = 0, *r = 0;
  size_t mlen = kp->params->msgsize;
  int rv;

  BN_init(&u);
  BN_init(&x);
  BN_init(&y);

  if (use_curve0) {
    ca = kp->params->c0;
    ga = kp->params->g0;
    pa = kp->p0;
    FAILZ(BN_copy(&u, uraw));
  } else {
    ca = kp->params->c1;
    ga = kp->params->g1;
    pa = kp->p1;
    FAILZ(BN_sub(&u, uraw, kp->params->n0));
    FAILZ(BN_add(&u, &u, BN_value_one()));
  }

  FAILZ(q = EC_POINT_new(ca));
  FAILZ(r = EC_POINT_new(ca));
  FAILZ(EC_POINT_mul(ca, q, 0, ga, &u, kp->params->ctx));
  FAILZ(EC_POINT_mul(ca, r, 0, pa, &u, kp->params->ctx));

  FAILZ(EC_POINT_get_affine_coordinates_GF2m(ca, q, &x, &y, kp->params->ctx));
  if (bn2bin_padhi(&x, message, mlen) != mlen)
    goto fail;
  if (message[0] & kp->params->padmask) /* see below */
    goto fail;
  memcpy(secret, message, mlen);

  FAILZ(EC_POINT_get_affine_coordinates_GF2m(ca, r, &x, &y, kp->params->ctx));
  if (bn2bin_padhi(&x, secret + mlen, mlen) != mlen)
    goto fail;

  /* K high bits of the message will be zero.  Fill in K-1 of them
     with random bits from the pad, and use the highest bit to
     identify the curve in use.  That bit will have a bias on the
     order of 2^{-d/2} where d is the bit-degree of the curve; 2^{-81}
     for the only curve presently implemented.  This is acceptably
     small since an elliptic curve of d bits gives only about d/2 bits
     of security anyway, and is much better than allowing a timing
     attack via the recipient having to attempt point decompression
     twice for curve 1 but only once for curve 0. */

  pad &= kp->params->padmask;
  pad &= 0x7F;
  pad |= (use_curve0 ? 0 : 0x80);
  message[0] |= pad;

  rv = 0;
 done:
  BN_clear(&u);
  BN_clear(&x);
  BN_clear(&y);
  if (q) EC_POINT_clear_free(q);
  if (r) EC_POINT_clear_free(r);
  return rv;

 fail:
  memset(message, 0, mlen);
  memset(secret, 0, mlen * 2);
  rv = -1;
  goto done;
}

int
MKEM_decode_message(const MKEM *kp, uint8_t *secret, const uint8_t *message)
{
  int use_curve0 = !(message[0] & 0x80);
  const EC_GROUP *ca = use_curve0 ? kp->params->c0 : kp->params->c1;
  const BIGNUM *sa = use_curve0 ? kp->s0 : kp->s1;
  EC_POINT *q = 0, *r = 0;
  uint8_t *unpadded = 0;
  BIGNUM x, y;
  size_t mlen = kp->params->msgsize;
  int rv;

  if (!kp->s0 || !kp->s1) /* secret key not available */
    return -1;

  BN_init(&x);
  BN_init(&y);
  FAILZ(q = EC_POINT_new(ca));
  FAILZ(r = EC_POINT_new(ca));
  FAILZ(unpadded = malloc(mlen + 1));

  /* Copy the message, erase the padding bits, and put an 0x02 byte on
     the front so we can use EC_POINT_oct2point to recover the
     y-coordinate. */
  unpadded[0] = 0x02;
  unpadded[1] = (message[0] & ~kp->params->padmask);
  memcpy(&unpadded[2], &message[1], mlen - 1);

  FAILZ(EC_POINT_oct2point(ca, q, unpadded, mlen + 1,
                           kp->params->ctx));
  FAILZ(EC_POINT_mul(ca, r, 0, q, sa, kp->params->ctx));

  FAILZ(EC_POINT_get_affine_coordinates_GF2m(ca, q, &x, &y, kp->params->ctx));
  if (bn2bin_padhi(&x, secret, mlen) != mlen)
    goto fail;

  FAILZ(EC_POINT_get_affine_coordinates_GF2m(ca, r, &x, &y, kp->params->ctx));
  if (bn2bin_padhi(&x, secret + mlen, mlen) != mlen)
    goto fail;

  rv = 0;
 done:
  if (unpadded) {
    memset(unpadded, 0, mlen + 1);
    free(unpadded);
  }
  if (q) EC_POINT_clear_free(q);
  if (r) EC_POINT_clear_free(r);
  BN_clear(&x);
  BN_clear(&y);
  return rv;

 fail:
  rv = -1;
  memset(secret, 0, mlen * 2);
  goto done;
}


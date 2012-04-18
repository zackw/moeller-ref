/* Reference implementation of Moeller 2004, "A Public-Key Encryption
   Scheme with Pseudo-Random Ciphertexts" (key encapsulation only).
   Written and placed in the public domain by Zack Weinberg, 2012.
   N.B. This file must be compilable as either C or C++. */

#ifndef _MREF_CURVES_H_
#define _MREF_CURVES_H_

#include <stddef.h>
#include <stdint.h>

/* Encapsulation of a set of elliptic curve parameters. */

typedef struct mk_curve_params
{
  /* generating polynomial, aka reducing polynomial, aka modulus: bignum */
  const uint8_t *m;
  size_t       L_m;

  /* elliptic curve coefficient 'b': bignum */
  const uint8_t *b;
  size_t       L_b;

  /* curve group large primes: bignum */
  const uint8_t *p0;
  size_t       L_p0;
  const uint8_t *p1;
  size_t       L_p1;

  /* curve group sizes: bignum */
  const uint8_t *n0;
  size_t       L_n0;
  const uint8_t *n1;
  size_t       L_n1;

  /* curve group generators: points (SEC1 compressed format) */
  const uint8_t *g0;
  size_t       L_g0;
  const uint8_t *g1;
  size_t       L_g1;

} mk_curve_params;

/* All the known curves that can be used with this algorithm are
   defined by mk_curve_params objects in this array. */
extern const mk_curve_params mk_curves[];

/* MK_CURVE_nbits_index constants are indices into the mk_curves
   array, corresponding to particular curves of interest. */

enum {
  MK_CURVE_163_0  /* original 163-bit curve from Moeller 2004 */
};

#endif

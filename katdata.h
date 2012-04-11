/* Known-answer tests for Moeller KEM -- data.
   Written and placed in the public domain by Zack Weinberg, 2012.
   N.B. This file must be compilable as either C or C++. */

#ifndef _MREF_KATDATA_H_
#define _MREF_KATDATA_H_

#include <stddef.h>

typedef struct mk_test_key
{
  const unsigned char p0[22];
  const unsigned char p1[22];
  const unsigned char s0[21];
  const unsigned char s1[21];
} mk_test_key;

enum { mk_n_reference_keys = 4 };
extern const mk_test_key mk_reference_keys[mk_n_reference_keys];

// Note: Only the derived secret, not the message on the wire, depends
// on the public key.
typedef struct mk_test_message
{
  const unsigned char u[21];
  const unsigned char pad;
  const unsigned char m[21];

  const unsigned char s[mk_n_reference_keys][42];
} mk_test_message;

extern const size_t mk_n_reference_messages;
extern const mk_test_message mk_reference_messages[];

#endif

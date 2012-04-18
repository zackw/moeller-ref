/* Known-answer tests for Moeller KEM -- openssl version.
   Written and placed in the public domain by Zack Weinberg, 2012. */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <openssl/err.h>

#include "mref-o.h"
#include "katdata.h"

static int set_failure = 0;
static int failure = 0;

static void
print_hexarray(const uint8_t *b, size_t n, const char *prefix)
{
  const uint8_t *limit = b + n;
  fputs(prefix, stdout);
  while (b < limit)
    printf("%02x", *b++);
}

static void
print_bignum(const BIGNUM *i, size_t n)
{
  char *hex = BN_bn2hex(i);
  char *p;
  size_t l = strlen(hex);

  while (l < n*2) {
    putchar('0');
    l++;
  }

  for (p = hex; *p; p++)
    *p = tolower(*p);

  fputs(hex, stdout);
  OPENSSL_free(hex);
}

static void
report_failure(const char *label, ...)
{
  va_list ap;

  if (!set_failure) {
    fputs("FAIL\n", stdout);
    set_failure = 1;
    failure = 1;
  }

  va_start(ap, label);
  vprintf(label, ap);
  va_end(ap);
  putchar('\n');

  ERR_print_errors_fp(stdout);
}

static void
compare_failure(const uint8_t *got, const uint8_t *exp, size_t len,
                const char *label)
{
  report_failure(label);
  print_hexarray(exp, len, " expected: ");
  putchar('\n');
  print_hexarray(got, len, "      got: ");
  putchar('\n');
}

static void
test_one(const MKEM *sk, const MKEM *pk, const BIGNUM *u, uint8_t pad,
         const uint8_t *sr, size_t srlen, const uint8_t *mr, size_t mrlen)
{
  uint8_t *s, *m;
  size_t slen, mlen;

  slen = sk->params->msgsize * 2;
  mlen = sk->params->msgsize;

  if (mlen != pk->params->msgsize) {
    report_failure("size inconsistency: sk->msgsize=%lu pk->msgsize=%lu",
                   (unsigned long)mlen, (unsigned long)pk->params->msgsize);
    return;
  }
  if (slen != srlen) {
    report_failure("size inconsistency: slen=%lu srlen=%lu",
                   (unsigned long)slen, (unsigned long)srlen);
    return;
  }
  if (mlen != mrlen) {
    report_failure("size inconsistency: mlen=%lu mrlen=%lu",
                   (unsigned long)mlen, (unsigned long)mrlen);
    return;
  }

  s = malloc(slen);
  m = malloc(mlen);
  if (!s || !m) {
    report_failure("memory allocation failure");
    exit(1);
  }

  /* Both the public and the secret key should generate the same secret
     and message strings as the references. */
  if (MKEM_generate_message_u(pk, u, pad, s, m)) {
    report_failure("pubkey generate message failed");
  } else {
    if (memcmp(s, sr, slen))
      compare_failure(s, sr, slen, "secret (pubkey):");
    if (memcmp(m, mr, mlen))
      compare_failure(m, mr, mlen, "message (pubkey):");
  }

  if (MKEM_generate_message_u(sk, u, pad, s, m)) {
    report_failure("seckey generate message failed");
  } else {
    if (memcmp(s, sr, slen))
      compare_failure(s, sr, slen, "secret (seckey):");
    if (memcmp(m, mr, mlen))
      compare_failure(m, mr, mlen, "message (seckey):");
  }

  /* Decoding the message string with the secret key should also
     reproduce the secret string. */
  if (MKEM_decode_message(sk, s, mr)) {
    report_failure("decode message failed");
  } else if (memcmp(s, sr, slen)) {
    compare_failure(s, sr, slen, "roundtrip:");
  }

  free(s);
  free(m);
}

static void
test_set(const MKEMParams *params, const mk_test_message *set)
{
  BIGNUM *u;
  size_t i;
  MKEM sk, pk;

  set_failure = 0;
  memset(&sk, 0, sizeof(MKEM));
  memset(&pk, 0, sizeof(MKEM));
  u = BN_bin2bn(set->u, sizeof set->u, 0);
  if (!u) {
    report_failure("decoding 'u'");
    return;
  }
  printf("%02x|", set->pad);
  print_bignum(u, params->msgsize);
  fputs("... ", stdout);
  fflush(stdout);

  for (i = 0; i < mk_n_reference_keys; i++) {
    if (MKEM_init_sk_vec(&sk, params,
                         mk_reference_keys[i].s0,
                         sizeof mk_reference_keys[i].s0,
                         mk_reference_keys[i].s1,
                         sizeof mk_reference_keys[i].s1)) {
      report_failure("creating seckey");
      goto skip;
    }
    if (MKEM_init_pk_vec(&pk, params,
                         mk_reference_keys[i].p0,
                         sizeof mk_reference_keys[i].p0,
                         mk_reference_keys[i].p1,
                         sizeof mk_reference_keys[i].p1)) {
      report_failure("creating pubkey");
      goto skip;
    }

    test_one(&sk, &pk, u, set->pad, set->s[i], sizeof set->s[i],
             set->m, sizeof set->m);

    skip:
      MKEM_teardown(&sk);
      MKEM_teardown(&pk);
  }

  if (!set_failure)
    fputs("ok\n", stdout);

  BN_free(u);
}

int
main(void)
{
  size_t i;
  MKEMParams params;

  ERR_load_crypto_strings();

  if (MKEMParams_init(&params)) {
    report_failure("initializing MKEMParams");
    return 1;
  }

  failure = 0;
  for (i = 0; i < mk_n_reference_messages; i++)
    test_set(&params, &mk_reference_messages[i]);

  return failure;
}

// Known-answer tests for Moeller KEM -- crypto++ version.
// Written and placed in the public domain by Zack Weinberg, 2012.

#include <iostream>
#include <iomanip>
#include <cryptopp/osrng.h>
#include "mref-c.h"
#include "katdata.h"

using CryptoPP::SecByteBlock;
using CryptoPP::Integer;
using std::cout;

static bool set_failure = false;
static bool failure = false;

static void
print_hexarray(SecByteBlock const& b, char const* prefix)
{
  cout << prefix;
  for (SecByteBlock::const_iterator i = b.begin(); i != b.end(); i++) {
    cout << std::hex << std::setw(2) << std::setfill('0')
         << (unsigned int)(*i);
  }
}

static void
print_hexint(Integer const& i, size_t nbytes)
{
  SecByteBlock b(nbytes);
  i.Encode(b.data(), nbytes);
  print_hexarray(b, "");
}

static void
report_failure(char const* label, char const* what = 0)
{
  if (!set_failure) {
    cout << "FAIL\n";
    set_failure = true;
    failure = true;
  }
  cout << label;
  if (what)
    cout << ": " << what;
  cout << '\n';
}

static void
report_failure(SecByteBlock const& got,
               SecByteBlock const& exp,
               char const* label)
{
  report_failure(label);
  print_hexarray(exp, " expected: ");
  cout << '\n';
  print_hexarray(got, "      got: ");
  cout << '\n';
}

static void
test_one(MKEM const& sk, MKEM const& pk, Integer const& u, byte pad,
         SecByteBlock const& sref, SecByteBlock const& mref)
{
  SecByteBlock s, m;

  // Both the public and the secret key should generate the same secret
  // string and message string as the references.
  pk.GenerateMessage(u, pad, s, m);
  if (s != sref)
    report_failure(s, sref, "secret (pubkey):");
  if (m != mref)
    report_failure(m, mref, "message (pubkey):");

  sk.GenerateMessage(u, pad, s, m);
  if (s != sref)
    report_failure(s, sref, "secret (seckey):");
  if (m != mref)
    report_failure(m, mref, "message (seckey):");

  // Decoding the message string with the secret key should also
  // reproduce the secret string.
  SecByteBlock so;
  try {
    sk.DecodeMessage(mref, so);
    if (s != so)
      report_failure(s, so, "roundtrip:");
  } catch (CryptoPP::Exception const& e) {
    report_failure("decode error", e.what());
  }
}

static void
test_set(MKEMParams const& params, mk_test_message const* set)
{
  set_failure = false;

  Integer u(set->u, sizeof set->u);
  SecByteBlock mref(set->m, sizeof set->m);

  cout << std::hex << std::setw(2) << std::setfill('0')
       << (unsigned int)(set->pad) << '|';
  print_hexint(u, params.MsgSize());
  cout << "... " << std::flush;

  for (size_t i = 0; i < mk_n_reference_keys; i++) {
    MKEM sk(params, true,
            mk_reference_keys[i].s0, sizeof mk_reference_keys[i].s0,
            mk_reference_keys[i].s1, sizeof mk_reference_keys[i].s1);
    MKEM pk(params, false,
            mk_reference_keys[i].p0, sizeof mk_reference_keys[i].p0,
            mk_reference_keys[i].p1, sizeof mk_reference_keys[i].p1);
    SecByteBlock sref(set->s[i], sizeof set->s[i]);
    test_one(sk, pk, u, set->pad, sref, mref);
  }

  if (!set_failure)
    cout << "ok\n";
}

int
main()
{
  try {
    MKEMParams params;

    for (size_t i = 0; i < mk_n_reference_messages; i++)
      test_set(params, &mk_reference_messages[i]);
  } catch(std::exception const& e) {
    report_failure("exception", e.what());
    return 2;
  } catch (...) {
    report_failure("exception of unknown type");
    return 2;
  }

  return failure;
}

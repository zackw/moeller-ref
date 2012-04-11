// Known-answer test generator for Moeller KEM -- Crypto++ version.
// Written and placed in the public domain by Zack Weinberg, 2012.

#include <iostream>
#include <iomanip>
#include <vector>

#include <cryptopp/rng.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>

#include "mref-c.h"

using CryptoPP::AES;
using CryptoPP::BufferedTransformation;
using CryptoPP::Integer;
using CryptoPP::SHA256;
using CryptoPP::SecByteBlock;
using CryptoPP::X917RNG;
using CryptoPP::lword;
using CryptoPP::member_ptr;

using std::cout;
using std::cerr;
using std::string;
using std::vector;

bool failure = false;

namespace {

class DeterministicRNG : public CryptoPP::RandomNumberGenerator,
                         public CryptoPP::NotCopyable
{
  static const char seedtext[385];
  static const byte timev[16];

  member_ptr<X917RNG> impl;

public:
  explicit DeterministicRNG()
  {
    byte hash[32];
    SHA256().CalculateDigest(hash, (const byte *)seedtext, sizeof seedtext - 1);

    impl.reset(new X917RNG(new AES::Encryption(hash + 16, 16),
                           hash, timev));
  }

  void GenerateIntoBufferedTransformation(BufferedTransformation &t,
                                          const string &c, lword l)
  {
    impl->GenerateIntoBufferedTransformation(t, c, l);
  }
};

const char DeterministicRNG::seedtext[385] =
  "All of the random numbers in this program's output are generated "
  "deterministically, using the ANSI X9.17 Appendix C secure random "
  "number generator algorithm, with AES-128 as the block cipher for "
  "that algorithm, the high half of the SHA-256 hash of this string "
  "as the seed, the low half of that hash as the key, and a hundred "
  "twenty-eight binary zeros as the deterministic time vector.";

const byte DeterministicRNG::timev[16] = {};

} // anon namespace

static void
print_hexarray(SecByteBlock const& b, const char* indent)
{
  cout << '{';
  int n = 0;

  for (SecByteBlock::const_iterator i = b.begin(); i != b.end(); ) {
    if (n == 11) {
      cout << '\n' << indent;
      n = 0;
    }
    cout << " 0x"
         << std::hex << std::setw(2) << std::setfill('0')
         << (unsigned int)(*i);
    n++;
    i++;
    if (i != b.end())
      cout << ',';
  }
  cout << " }";
}

static void
one_test_vector(MKEM const& key, Integer const& u, byte pad,
                SecByteBlock& m_out)
{
  SecByteBlock s, m;
  key.GenerateMessage(u, pad, s, m);
  SecByteBlock so;
  try {
    key.DecodeMessage(m, so);
    if (s != so) {
      cerr << u << ": round-trip failure: s != so\n";
      failure = true;
    }
  } catch (CryptoPP::Exception const& e) {
    cerr << u << ": decode error: " << e.what() << '\n';
    failure = true;
  }

  if (m_out.empty()) {
    m_out = m;
    print_hexarray(m, "     ");
    cout << ",\n\n    { ";
  } else {
    if (m != m_out) {
      cerr << u << ": cross-key message disagreement\n";
      failure = true;
    }
  }

  print_hexarray(s, "       ");
}

static void
one_test_number(Integer const& u, byte pad, vector<MKEM> const& keys)
{
  cout << "  /* "
       << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(pad)
       << '|' << std::dec << u
       << " */\n  { ";
  SecByteBlock uu;
  uu.New(21);
  u.Encode(uu.data(), 21);
  print_hexarray(uu, "     ");

  cout << ", 0x" << std::hex << std::setw(2) << std::setfill('0')
       << (unsigned int)(pad) << ",\n    ";

  SecByteBlock mcache;

  for (vector<MKEM>::const_iterator i = keys.begin();;) {
    one_test_vector(*i, u, pad, mcache);
    i++;
    if (i == keys.end())
      break;
    cout << ",\n      ";
  }

  cout << " } }";
}

static void
all_test_numbers(MKEMParams const& params, DeterministicRNG& rng,
                 vector<MKEM> const& keys)
{
  cout << "const mk_test_message mk_reference_messages[] = {\n";

  // evenly spaced values covering the overall number space
  Integer mu(params.MaxU());
  Integer stride(mu); stride /= Integer(12);
  Integer u(stride);  u /= Integer::Two();

  for (; u.Compare(mu) < 0; u += stride) {
    // each test number with all-zero and all-one pad
    one_test_number(u, 0x00, keys); cout << ",\n\n";
    one_test_number(u, 0xFF, keys); cout << ",\n\n";
  }

  // two random values from the n0 space
  Integer h(mu);
  h /= Integer::Two();
  h -= stride;

  u = Integer(rng, Integer::One(), h);
  byte pad = rng.GenerateByte();
  one_test_number(u, pad, keys);
  cout << ",\n\n";

  u = Integer(rng, Integer::One(), h);
  pad = rng.GenerateByte();
  one_test_number(u, pad, keys);
  cout << ",\n\n";

  // two random values from the n1 space
  h += stride;
  h += stride;

  u = Integer(rng, h, mu);
  pad = rng.GenerateByte();
  one_test_number(u, pad, keys);
  cout << ",\n\n";

  u = Integer(rng, h, mu);
  pad = rng.GenerateByte();
  one_test_number(u, pad, keys);

  cout << "\n};\n"
       << "const size_t mk_n_reference_messages =\n"
       << "  sizeof mk_reference_messages / sizeof mk_reference_messages[0];\n";
}

static void
all_test_keys(MKEMParams const& params, DeterministicRNG& rng,
              vector<MKEM>& keys)
{
  CryptoPP::SecByteBlock p0, p1, s0, s1;

  cout << "const mk_test_key mk_reference_keys[] = {\n";

  for (int i = 0;;) {
    MKEM key(params, rng);
    keys.push_back(key);

    key.ExportPublicKey(p0, p1);
    key.ExportSecretKey(s0, s1);

    cout << "  /* " << std::dec << i << " */\n  { ";
    print_hexarray(p0, "     "); cout << ",\n    ";
    print_hexarray(p1, "     "); cout << ",\n\n    ";
    print_hexarray(s0, "     "); cout << ",\n    ";
    print_hexarray(s1, "     "); cout << " }";

    if (++i == 4) break;
    cout << ",\n\n";
  }
  cout << "\n};\n\n";
}

int
main()
{
  MKEMParams params;
  DeterministicRNG rng;

  cout <<
    "/* Known-answer tests for Moeller KEM -- data.\n"
    "   This file is mechanically generated.  DO NOT EDIT.\n"
    "   Modify katgen.cc instead. */\n"
    "\n"
    "#include \"katdata.h\"\n"
    "\n";

  vector<MKEM> keys;
  all_test_keys(params, rng, keys);
  all_test_numbers(params, rng, keys);

  return failure;
}

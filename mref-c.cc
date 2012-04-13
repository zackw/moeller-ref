// Reference implementation of Moeller 2004, "A Public-Key Encryption
// Scheme with Pseudo-Random Ciphertexts" (key encapsulation only).
// Written and placed in the public domain by Zack Weinberg, 2012.

#include "mref-c.h"

using CryptoPP::Integer;
using CryptoPP::RandomNumberGenerator;
using CryptoPP::SecByteBlock;
using CryptoPP::InvalidArgument;
using CryptoPP::InvalidCiphertext;

typedef MKEMParams::Point Point;
typedef MKEMParams::Curve Curve;

// Fixed algorithm parameters

// generating polynomial / reducing polynomial / modulus
static byte m_[] = { 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC9 };

// elliptic curve coefficient 'b'
static byte b_[] = { 0x05, 0x84, 0x6d, 0x0f, 0xda, 0x25, 0x53,
                     0x61, 0x60, 0x67, 0x11, 0xbf, 0x7a, 0x99,
                     0xb0, 0x72, 0x2e, 0x2e, 0xc8, 0xf7, 0x6b };

// curve group large primes
// 2923003274661805836407371179614143033958162426611
static byte p0_[] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x01, 0x40, 0xa3, 0xf2,
                      0xa0, 0xc6, 0xce, 0xd9, 0xce, 0xea, 0xf3 };

// 5846006549323611672814736302501978089331135490587
static byte p1_[] = { 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xfd, 0x7e, 0xb8, 0x1a,
                      0xbe, 0x72, 0x62, 0x4c, 0x62, 0x2a, 0x1b };

// curve group sizes
// 4 * 2923003274661805836407371179614143033958162426611
static byte n0_[] = { 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x05, 0x02, 0x8f, 0xca,
                      0x83, 0x1b, 0x3b, 0x67, 0x3b, 0xab, 0xcc };

// 2 * 5846006549323611672814736302501978089331135490587
static byte n1_[] = { 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xfa, 0xfd, 0x70, 0x35,
                      0x7c, 0xe4, 0xc4, 0x98, 0xc4, 0x54, 0x36 };

// curve group generators
// Crypto++ uses the compressed point format defined in Certicom SEC 1
// ("Standards for Efficient Cryptography 1").  The sign of y in these
// points shouldn't matter.
static byte g0_[] = { 0x02,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
static byte g1_[] = { 0x02,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };

MKEMParams::MKEMParams()
  : m(m_, sizeof m_), b(b_, sizeof b_), a0(0), a1(1), f(m),
    c0(f, a0, b),
    c1(f, a1, b),
    p0(p0_, sizeof p0_),
    p1(p1_, sizeof p1_),
    n0(n0_, sizeof n0_),
    n1(n1_, sizeof n1_)
{
  c0.DecodePoint(g0, g0_, sizeof g0_);
  c1.DecodePoint(g1, g1_, sizeof g1_);

  // Calculate the upper limit for the random integer U input to
  // GenerateMessage.
  //
  // The paper calls for us to choose between curve 0 and curve 1 with
  // probability proportional to the number of points on that curve, and
  // then choose a random integer in the range 0 < u < n{curve}.  The
  // easiest way to do this accurately is to choose a random integer in the
  // range [1, n0 + n1 - 2].  If it is less than n0, MKEM::GenerateMessage
  // will use it unmodified with curve 0.  If it is greater than or equal
  // to n0, MKEM::GenerateMessage will subtract n0-1, leaving a number in
  // the range [1, n1-1], and use that with curve 1.
  maxu = n0;
  maxu += n1;
  maxu -= Integer::Two();

  // Calculate the padding mask applied to the high byte of each message.
  // See GenerateMessage for explanation.
  size_t bitsize = f.MaxElementBitLength();
  size_t bitcap  = f.MaxElementByteLength() * 8;
  size_t k = bitcap - bitsize;
  byte mask = ~((1 << (8-k)) - 1);
  if (mask == 0)
    throw InvalidArgument("bad curve parameters - no space for tag bit");
  padmask = mask;
}

// The secret integers s0 and s1 must be in the range 0 < s < n for
// some n, and must be relatively prime to that n.  We know a priori
// that n is of the form 2**k * p for some small integer k and prime
// p.  Therefore, it suffices to choose a random integer in the range
// [0, n/2) which is not divisible by p, and then multiply by two and
// add one (enforcing oddness).
static Integer
random_s(RandomNumberGenerator& rng, Integer const& n, Integer const& p)
{
  Integer h(n);
  h >>= 1;
  h --;
  for (;;) {
    Integer r(rng, Integer::One(), h);
    if (r.Modulo(p).Compare(Integer::Zero()) == 0)
      continue;
    r <<= 1;
    r ++;
    return r;
  }
}

MKEM::MKEM(MKEMParams const& params_,
           RandomNumberGenerator& rng_)
  : params(&params_),
    s0(random_s(rng_, params->n0, params->p0)),
    s1(random_s(rng_, params->n1, params->p1)),
    p0(params->c0.Multiply(s0, params->g0)),
    p1(params->c1.Multiply(s1, params->g1)),
    have_sk(true)
{
}

MKEM::MKEM(MKEMParams const& params_,
           Integer const& s0_,
           Integer const& s1_)
  : params(&params_),
    s0(s0_), s1(s1_),
    p0(params->c0.Multiply(s0, params->g0)),
    p1(params->c1.Multiply(s1, params->g1)),
    have_sk(true)
{}

MKEM::MKEM(MKEMParams const& params_,
           Point const& p0_,
           Point const& p1_)
  : params(&params_),
    s0(), s1(),
    p0(p0_), p1(p1_),
    have_sk(false)
{}

MKEM::MKEM(MKEMParams const& params_, bool is_secret_key,
           const byte *v0, size_t v0l,
           const byte *v1, size_t v1l)
  : params(&params_),
    s0(), s1(), p0(), p1(),
    have_sk(is_secret_key)
{
  if (is_secret_key) {
    s0.Decode(v0, v0l);
    s1.Decode(v1, v1l);
    p0 = params->c0.Multiply(s0, params->g0);
    p1 = params->c1.Multiply(s1, params->g1);
  } else {
    params->c0.DecodePoint(p0, v0, v0l);
    params->c1.DecodePoint(p1, v1, v1l);
  }
}

void
MKEM::ExportPublicKey(Point& p0_, Point& p1_) const
{
  p0_ = p0;
  p1_ = p1;
}

void
MKEM::ExportPublicKey(SecByteBlock& p0_, SecByteBlock& p1_) const
{
  p0_.New(params->c0.EncodedPointSize(true));
  p1_.New(params->c1.EncodedPointSize(true));
  params->c0.EncodePoint(p0_.data(), p0, true);
  params->c1.EncodePoint(p1_.data(), p1, true);
}

void
MKEM::ExportSecretKey(Integer& s0_, Integer& s1_) const
{
  if (!have_sk)
    throw InvalidArgument("secret key not available");
  s0_ = s0;
  s1_ = s1;
}

void
MKEM::ExportSecretKey(SecByteBlock& s0_, SecByteBlock& s1_) const
{
  if (!have_sk)
    throw InvalidArgument("secret key not available");
  size_t sz = params->MsgSize();
  s0_.New(sz);
  s1_.New(sz);
  s0.Encode(s0_.data(), sz);
  s1.Encode(s1_.data(), sz);
}

void
MKEM::GenerateMessage(Integer const& u_,
                      byte pad,
                      SecByteBlock& secret,
                      SecByteBlock& message) const
{
  bool use_curve0 = u_.Compare(params->n0) == -1;
  Curve const& ca(use_curve0 ? params->c0 : params->c1);
  Point const& ga(use_curve0 ? params->g0 : params->g1);
  Point const& pa(use_curve0 ? p0 : p1);
  Integer u(u_);
  if (!use_curve0) {
    u -= params->n0;
    u++;
  }

  Point q(ca.Multiply(u, ga));
  Point r(ca.Multiply(u, pa));
  size_t eltsize = params->MsgSize();

  message.New(eltsize);
  secret.New(eltsize * 2);
  q.x.Encode(message.data(), eltsize);
  memcpy(secret.data(), message.data(), eltsize);
  r.x.Encode(secret.data() + eltsize, eltsize);

  // K high bits of the message will be zero.  Fill in K-1 of them
  // with random bits from the pad, and use the highest bit to
  // identify the curve in use.  That bit will have a bias on the
  // order of 2^{-d/2} where d is the bit-degree of the curve; 2^{-81}
  // for the only curve presently implemented.  This is acceptably
  // small since an elliptic curve of d bits gives only about d/2 bits
  // of security anyway, and is much better than allowing a timing
  // attack via the recipient having to attempt point decompression
  // twice for curve 1 but only once for curve 0.

  if (message.data()[0] & params->padmask)
    throw InvalidCiphertext("bits expected to be zero are nonzero");

  pad &= params->padmask;
  pad &= 0x7F;
  pad |= (use_curve0 ? 0 : 0x80);
  message.data()[0] |= pad;
}

void
MKEM::GenerateMessage(CryptoPP::RandomNumberGenerator& rng,
                      CryptoPP::SecByteBlock& secret,
                      CryptoPP::SecByteBlock& message) const
{
  CryptoPP::Integer u(rng, CryptoPP::Integer::One(), params->MaxU());
  byte pad = rng.GenerateByte();
  GenerateMessage(u, pad, secret, message);
}

void
MKEM::DecodeMessage(SecByteBlock const& message,
                    SecByteBlock& secret) const
{
  if (!have_sk)
    throw InvalidArgument("secret key not available");

  Point q;
  bool use_curve0 = !(message[0] & 0x80);
  Curve const& ca(use_curve0 ? params->c0 : params->c1);
  Integer const& sa(use_curve0 ? s0 : s1);

  // Copy the message, erase the padding bits, and put an 0x02 byte on
  // the front so we can use DecodePoint() to recover the y-coordinate.
  SecByteBlock unpadded(message.size() + 1);
  unpadded[0] = 0x02;
  unpadded[1] = (message[0] & ~params->padmask);
  memcpy(&unpadded[2], &message[1], message.size() - 1);

  if (!ca.DecodePoint(q, unpadded.data(), unpadded.size()) || q.identity)
    throw InvalidCiphertext("point not on curve, or at infinity");

  Point r(ca.Multiply(sa, q));
  size_t eltsize = params->MsgSize();

  secret.New(eltsize * 2);
  q.x.Encode(secret.data(), eltsize);
  r.x.Encode(secret.data() + eltsize, eltsize);
}

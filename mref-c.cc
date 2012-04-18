// Reference implementation of Moeller 2004, "A Public-Key Encryption
// Scheme with Pseudo-Random Ciphertexts" (key encapsulation only).
// Written and placed in the public domain by Zack Weinberg, 2012.

#include "mref-c.h"
#include "curves.h"

using CryptoPP::Integer;
using CryptoPP::RandomNumberGenerator;
using CryptoPP::SecByteBlock;
using CryptoPP::InvalidArgument;
using CryptoPP::InvalidCiphertext;

typedef MKEMParams::Point Point;
typedef MKEMParams::Curve Curve;

MKEMParams::MKEMParams()
  : m(mk_curves[MK_CURVE_163_0].m, mk_curves[MK_CURVE_163_0].L_m),
    b(mk_curves[MK_CURVE_163_0].b, mk_curves[MK_CURVE_163_0].L_b),
    a0(0),
    a1(1),
    f(m),
    c0(f, a0, b),
    c1(f, a1, b),
    p0(mk_curves[MK_CURVE_163_0].p0, mk_curves[MK_CURVE_163_0].L_p0),
    p1(mk_curves[MK_CURVE_163_0].p1, mk_curves[MK_CURVE_163_0].L_p1),
    n0(mk_curves[MK_CURVE_163_0].n0, mk_curves[MK_CURVE_163_0].L_n0),
    n1(mk_curves[MK_CURVE_163_0].n1, mk_curves[MK_CURVE_163_0].L_n1)
{
  c0.DecodePoint(g0,
                 mk_curves[MK_CURVE_163_0].g0, mk_curves[MK_CURVE_163_0].L_g0);
  c1.DecodePoint(g1,
                 mk_curves[MK_CURVE_163_0].g1, mk_curves[MK_CURVE_163_0].L_g1);

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
// [0, n/2), multiply by two and add one (enforcing oddness), and then
// reject values which are divisible by p.
static Integer
random_s(RandomNumberGenerator& rng, Integer const& n, Integer const& p)
{
  Integer h(n);
  h >>= 1;
  h --;
  for (;;) {
    Integer r(rng, Integer::Zero(), h);
    r <<= 1;
    r ++;
    if (r.Modulo(p).Compare(Integer::Zero()) != 0)
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

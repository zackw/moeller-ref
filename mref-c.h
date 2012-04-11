// -*- Mode: C++ -*-
// Reference implementation of Moeller 2004, "A Public-Key Encryption
// Scheme with Pseudo-Random Ciphertexts" (key encapsulation only).
// Written and placed in the public domain by Zack Weinberg, 2012.

#ifndef _MREF_CRYPTOPP_H_
#define _MREF_CRYPTOPP_H_

#include <cryptopp/ec2n.h>

class MKEM;

class MKEMParams
{
public:
  typedef CryptoPP::EC2N                 Curve;
  typedef CryptoPP::EC2N::Point          Point;
  typedef CryptoPP::EC2N::Field          Field;
  typedef CryptoPP::EC2N::Field::Element Element;

  MKEMParams();
  ~MKEMParams() {}

  // Return the upper limit for the random integer U from which the
  // encapsulated key is derived.
  CryptoPP::Integer MaxU() const { return maxu; }

  // Return the length of a message in bytes.
  size_t MsgSize() const { return f.MaxElementByteLength(); }

private:
  Element m, b, a0, a1;
  Field f;
  Curve c0, c1;
  CryptoPP::Integer p0, p1, n0, n1, maxu;
  Point g0, g1;
  byte padmask;

  friend class MKEM;
};

class MKEM
{
public:
  ~MKEM() {}

  // Generate a brand new keypair from a source of randomness.
  MKEM(MKEMParams const& params, CryptoPP::RandomNumberGenerator& rng);

  // Load a secret key expressed as two integers (s0, s1),
  // and regenerate the public key from it.
  MKEM(MKEMParams const& params,
       CryptoPP::Integer const& s0,
       CryptoPP::Integer const& s1);

  // Load a public key expressed as two elliptic curve points (p0, p1).
  // Since the secret key is not available, the resulting object's
  // ExportSecretKey and DecodeMessage methods cannot be used; they
  // will throw CryptoPP::InvalidArgument if called.
  MKEM(MKEMParams const& params,
       MKEMParams::Point const& p0,
       MKEMParams::Point const& p1);

  // Load either a secret or public key from byte vectors.
  MKEM(MKEMParams const& params, bool is_secret_key,
       const byte *v0, size_t v0l,
       const byte *v1, size_t v1l);

  // Export the public key as a pair of points.
  void ExportPublicKey(MKEMParams::Point& p0, MKEMParams::Point& p1) const;
  void ExportPublicKey(CryptoPP::SecByteBlock& p0,
                       CryptoPP::SecByteBlock& p1) const;

  // Export the secret key as a pair of integers.
  void ExportSecretKey(CryptoPP::Integer& s0, CryptoPP::Integer& s1) const;
  void ExportSecretKey(CryptoPP::SecByteBlock& p0,
                       CryptoPP::SecByteBlock& p1) const;

  // Generate secret material K and encrypted message kk from a source of
  // randomness.  This does NOT carry out key derivation; the "secret"
  // output is what the paper describes as $\mathfrak{k} || encode(x_R)$,
  // not KDF of that.
  void GenerateMessage(CryptoPP::RandomNumberGenerator& rng,
                       CryptoPP::SecByteBlock& secret,
                       CryptoPP::SecByteBlock& message) const;

  // Same, but work from a preselected integer 'u', which must be in
  // the closed interval [1, params.MaxU()], and an extra byte's worth
  // of random bits for padding.
  //
  // This is exposed only for the sake of known-answer tests.  Use of
  // non-random 'u' or 'pad' invalidates system properties, as does
  // reuse of either value.
  void GenerateMessage(CryptoPP::Integer const& u,
                       byte pad,
                       CryptoPP::SecByteBlock& secret,
                       CryptoPP::SecByteBlock& message) const;

  // Decode an encrypted message.  As with GenerateMessage, the result
  // is NOT run through a KDF.
  // Throws CryptoPP::InvalidArgument if called when the secret key is
  // not available, and CryptoPP::InvalidCiphertext if the ciphertext is
  // invalid.
  void DecodeMessage(CryptoPP::SecByteBlock const& message,
                     CryptoPP::SecByteBlock& secret) const;

private:
  // This is a pointer _only_ because C++ doesn't let you
  // use operator= on a class with a reference member, and
  // we want to be able to put these in STL containers. Feh.
  MKEMParams const* params;
  CryptoPP::Integer s0;
  CryptoPP::Integer s1;
  MKEMParams::Point p0;
  MKEMParams::Point p1;
  bool have_sk;
};

#endif

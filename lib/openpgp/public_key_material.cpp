// OpenPGP public key material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_material.h>

#include <neopg/intern/cplusplus.h>

using namespace NeoPG;

std::unique_ptr<PublicKeyMaterial> PublicKeyMaterial::create_or_throw(
    PublicKeyAlgorithm algorithm, ParserInput& in) {
  switch (algorithm) {
    case PublicKeyAlgorithm::Rsa:
      return RsaPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Dsa:
      return DsaPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Elgamal:
      return ElgamalPublicKeyMaterial::create_or_throw(in);
    default:
      in.error("unknown public key algorithm");
  }
  // Never reached.
  return nullptr;
}

std::unique_ptr<RsaPublicKeyMaterial> RsaPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<RsaPublicKeyMaterial>();
  data->m_n.parse(in);
  data->m_e.parse(in);
  return data;
}

void RsaPublicKeyMaterial::write(std::ostream& out) const {
  m_n.write(out);
  m_e.write(out);
}

std::unique_ptr<DsaPublicKeyMaterial> DsaPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<DsaPublicKeyMaterial>();
  data->m_p.parse(in);
  data->m_q.parse(in);
  data->m_g.parse(in);
  data->m_y.parse(in);
  return data;
}

void DsaPublicKeyMaterial::write(std::ostream& out) const {
  m_p.write(out);
  m_q.write(out);
  m_g.write(out);
  m_y.write(out);
}

std::unique_ptr<ElgamalPublicKeyMaterial>
ElgamalPublicKeyMaterial::create_or_throw(ParserInput& in) {
  auto data = make_unique<ElgamalPublicKeyMaterial>();
  data->m_p.parse(in);
  data->m_g.parse(in);
  data->m_y.parse(in);
  return data;
}

void ElgamalPublicKeyMaterial::write(std::ostream& out) const {
  m_p.write(out);
  m_g.write(out);
  m_y.write(out);
}

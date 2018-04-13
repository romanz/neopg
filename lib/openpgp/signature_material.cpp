// OpenPGP signature material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/signature_material.h>

#include <neopg/intern/cplusplus.h>

using namespace NeoPG;

std::unique_ptr<SignatureMaterial> SignatureMaterial::create_or_throw(
    PublicKeyAlgorithm algorithm, ParserInput& in) {
  switch (algorithm) {
    case PublicKeyAlgorithm::Rsa:
      return RsaSignatureMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Dsa:
      return DsaSignatureMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Elgamal:
    case PublicKeyAlgorithm::ElgamalEncrypt:
      return ElgamalSignatureMaterial::create_or_throw(in);
    default:
      in.error("unknown public key algorithm");
  }
  // Never reached.
  return nullptr;
}

std::unique_ptr<RsaSignatureMaterial> RsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<RsaSignatureMaterial>();
  data->m_n.parse(in);
  data->m_e.parse(in);
  return data;
}

void RsaSignatureMaterial::write(std::ostream& out) const {
  m_n.write(out);
  m_e.write(out);
}

std::unique_ptr<DsaSignatureMaterial> DsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<DsaSignatureMaterial>();
  data->m_p.parse(in);
  data->m_q.parse(in);
  data->m_g.parse(in);
  data->m_y.parse(in);
  return data;
}

void DsaSignatureMaterial::write(std::ostream& out) const {
  m_p.write(out);
  m_q.write(out);
  m_g.write(out);
  m_y.write(out);
}

std::unique_ptr<ElgamalSignatureMaterial>
ElgamalSignatureMaterial::create_or_throw(ParserInput& in) {
  auto data = make_unique<ElgamalSignatureMaterial>();
  data->m_p.parse(in);
  data->m_g.parse(in);
  data->m_y.parse(in);
  return data;
}

void ElgamalSignatureMaterial::write(std::ostream& out) const {
  m_p.write(out);
  m_g.write(out);
  m_y.write(out);
}

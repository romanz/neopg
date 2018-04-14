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
    default:
      in.error("unknown public key algorithm");
  }
  // Never reached.
  return nullptr;
}

std::unique_ptr<RsaSignatureMaterial> RsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<RsaSignatureMaterial>();
  data->m_m_pow_d.parse(in);
  return data;
}

void RsaSignatureMaterial::write(std::ostream& out) const {
  m_m_pow_d.write(out);
}

std::unique_ptr<DsaSignatureMaterial> DsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<DsaSignatureMaterial>();
  data->m_r.parse(in);
  data->m_s.parse(in);
  return data;
}

void DsaSignatureMaterial::write(std::ostream& out) const {
  m_r.write(out);
  m_s.write(out);
}

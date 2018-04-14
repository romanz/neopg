// OpenPGP public key packet data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_data.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <botan/hash.h>

using namespace NeoPG;

namespace NeoPG {
namespace public_key_data {
using namespace pegtl;

struct algorithm : must<any> {};

struct created : must<bytes<4>> {};

struct days_valid : must<bytes<2>> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<algorithm> {
  template <typename Input>
  static void apply(const Input& in, PublicKeyAlgorithm& algorithm) {
    algorithm = static_cast<PublicKeyAlgorithm>(in.peek_byte());
  }
};

template <>
struct action<created> {
  template <typename Input>
  static void apply(const Input& in, uint32_t& created) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    auto val2 = (uint32_t)in.peek_byte(2);
    auto val3 = (uint32_t)in.peek_byte(3);
    created = (val0 << 24) + (val1 << 16) + (val2 << 8) + val3;
  }
};

template <>
struct action<days_valid> {
  template <typename Input>
  static void apply(const Input& in, uint16_t& days_valid) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    days_valid = (val0 << 8) + val1;
  }
};

}  // namespace public_key_data
}  // namespace NeoPG

std::unique_ptr<PublicKeyData> PublicKeyData::create_or_throw(
    PublicKeyVersion version, ParserInput& in) {
  // std::string orig_data{in.current(), in.size()};

  std::unique_ptr<PublicKeyData> public_key;
  switch (version) {
    case PublicKeyVersion::V2:
    case PublicKeyVersion::V3:
      public_key = V2o3PublicKeyData::create_or_throw(version, in);
      break;
    case PublicKeyVersion::V4:
      public_key = V4PublicKeyData::create_or_throw(in);
      break;
    default:
      in.error("unknown public key version");
  }
  if (in.size() != 0) in.error("trailing data in public key");

  // FIXME: We could now output the public_key and verify that it outputs to
  // exactly the same bytes as the original data.  This will make sure we can
  // calculate the fingerprint correctly.
  // std::stringstream out;
  // public_key->write(out);
  // assert(orig_data == out.str());
  return public_key;
}

std::unique_ptr<V2o3PublicKeyData> V2o3PublicKeyData::create_or_throw(
    PublicKeyVersion version, ParserInput& in) {
  auto packet = make_unique<V2o3PublicKeyData>(version);

  pegtl::parse<public_key_data::created, public_key_data::action>(
      in.m_impl->m_input, packet->m_created);
  pegtl::parse<public_key_data::days_valid, public_key_data::action>(
      in.m_impl->m_input, packet->m_days_valid);
  pegtl::parse<public_key_data::algorithm, public_key_data::action>(
      in.m_impl->m_input, packet->m_algorithm);

  packet->m_key = PublicKeyMaterial::create_or_throw(packet->m_algorithm, in);

  switch (packet->m_algorithm) {
    case PublicKeyAlgorithm::Rsa:
    case PublicKeyAlgorithm::RsaEncrypt:
    case PublicKeyAlgorithm::RsaSign:
      break;
    default:
      in.error("unknown v3 public key algorithm");
  }

  return packet;
}

void V2o3PublicKeyData::write(std::ostream& out) const {
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
  out << static_cast<uint8_t>(m_days_valid >> 8)
      << static_cast<uint8_t>(m_days_valid);
  out << static_cast<uint8_t>(m_algorithm);
  // FIXME: Really optional?  (Useful for testing)
  if (m_key) m_key->write(out);
}

std::vector<uint8_t> V2o3PublicKeyData::fingerprint() const {
  std::vector<uint8_t> fpr;
  if (!m_key)  // FIXME (will crash keyid)
    return fpr;

  auto md5 = Botan::HashFunction::create_or_throw("MD5");
  auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(m_key.get());
  md5->update(rsa->m_n.bits());
  md5->update(rsa->m_e.bits());
  fpr.resize(md5->output_length());
  md5->final(fpr.data());
  return fpr;
}

std::vector<uint8_t> V2o3PublicKeyData::keyid() const {
  auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(m_key.get());
  const std::vector<uint8_t>& n = rsa->m_n.bits();
  // FIXME: Do something if not enough octets in N.
  return std::vector<uint8_t>(n.end() - 8, n.end());
}

std::unique_ptr<V4PublicKeyData> V4PublicKeyData::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<V4PublicKeyData>();

  pegtl::parse<public_key_data::created, public_key_data::action>(
      in.m_impl->m_input, packet->m_created);
  pegtl::parse<public_key_data::algorithm, public_key_data::action>(
      in.m_impl->m_input, packet->m_algorithm);

  packet->m_key = PublicKeyMaterial::create_or_throw(packet->m_algorithm, in);
  // We accept all algorithms that are known to PublicKeyMaterial.

  return packet;
}

void V4PublicKeyData::write(std::ostream& out) const {
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
  out << static_cast<uint8_t>(m_algorithm);
  // FIXME: Really optional? (Useful for testing)
  if (m_key) m_key->write(out);
}

std::vector<uint8_t> V4PublicKeyData::fingerprint() const {
  std::vector<uint8_t> fpr;

  std::stringstream out;
  out << static_cast<uint8_t>(version());
  write(out);
  std::string public_key = out.str();
  // This may be truncated.
  uint16_t length = static_cast<uint16_t>(public_key.size());
  auto sha1 = Botan::HashFunction::create_or_throw("SHA-1");
  sha1->update(0x99);
  sha1->update(static_cast<uint8_t>(length >> 8));
  sha1->update(static_cast<uint8_t>(length));
  sha1->update(public_key);
  fpr.resize(sha1->output_length());
  sha1->final(fpr.data());
  return fpr;
}

std::vector<uint8_t> V4PublicKeyData::keyid() const {
  std::vector<uint8_t> fpr = fingerprint();
  return std::vector<uint8_t>(fpr.begin() + 12, fpr.end());
}

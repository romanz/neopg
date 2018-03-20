// OpenPGP public key packet (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace public_key_packet {
using namespace pegtl;

struct algorithm : must<any> {};

struct created : must<bytes<4>> {};

struct days_valid : must<bytes<2>> {};

struct version : must<any> {};

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
  }  // namespace public_key_packet
};   // namespace NeoPG

template <>
struct action<days_valid> {
  template <typename Input>
  static void apply(const Input& in, uint16_t& days_valid) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    days_valid = (val0 << 8) + val1;
  }
};

template <>
struct action<version> {
  template <typename Input>
  static void apply(const Input& in, PublicKeyPacket::Version& version) {
    version = static_cast<PublicKeyPacket::Version>(in.peek_byte());
  }
};

}  // namespace public_key_packet
}  // namespace NeoPG

std::unique_ptr<PublicKeyPacket> PublicKeyPacket::create(ParserInput& in) {
  try {
    return PublicKeyPacket::create_or_throw(in);
  } catch (const pegtl::parse_error&) {
    return nullptr;
  }
}

std::unique_ptr<PublicKeyPacket> PublicKeyPacket::create_or_throw(
    ParserInput& in) {
  std::unique_ptr<PublicKeyPacket> public_key;
  Version version;
  pegtl::parse<public_key_packet::version, public_key_packet::action>(
      in.m_impl->m_input, version);
  switch (version) {
    case Version::V2:
    case Version::V3:
      public_key = V2o3PublicKeyPacket::create_or_throw(version, in);
      break;
    case Version::V4:
      public_key = V4PublicKeyPacket::create_or_throw(in);
      break;
    default:
      in.error("unknown public key version");
  }
  if (in.size() != 0) in.error("trailing data in public key");
  return public_key;
}

std::unique_ptr<V2o3PublicKeyPacket> V2o3PublicKeyPacket::create_or_throw(
    Version version, ParserInput& in) {
  auto packet = make_unique<V2o3PublicKeyPacket>(version);

  pegtl::parse<public_key_packet::created, public_key_packet::action>(
      in.m_impl->m_input, packet->m_created);
  pegtl::parse<public_key_packet::days_valid, public_key_packet::action>(
      in.m_impl->m_input, packet->m_days_valid);
  pegtl::parse<public_key_packet::algorithm, public_key_packet::action>(
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

void V2o3PublicKeyPacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_version);
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

std::unique_ptr<V4PublicKeyPacket> V4PublicKeyPacket::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<V4PublicKeyPacket>();

  pegtl::parse<public_key_packet::created, public_key_packet::action>(
      in.m_impl->m_input, packet->m_created);
  pegtl::parse<public_key_packet::algorithm, public_key_packet::action>(
      in.m_impl->m_input, packet->m_algorithm);

  packet->m_key = PublicKeyMaterial::create_or_throw(packet->m_algorithm, in);
  // We accept all algorithms that are known to PublicKeyMaterial.

  return packet;
}

void V4PublicKeyPacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(Version::V4);
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
  out << static_cast<uint8_t>(m_algorithm);
  // FIXME: Really optional? (Useful for testing)
  if (m_key) m_key->write(out);
}

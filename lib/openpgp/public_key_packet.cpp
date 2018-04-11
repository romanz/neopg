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

struct version : must<any> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<version> {
  template <typename Input>
  static void apply(const Input& in, PublicKeyVersion& version) {
    version = static_cast<PublicKeyVersion>(in.peek_byte());
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
  PublicKeyVersion version;
  pegtl::parse<public_key_packet::version, public_key_packet::action>(
      in.m_impl->m_input, version);

  auto packet = make_unique<PublicKeyPacket>(version);
  packet->m_public_key = PublicKeyData::create_or_throw(version, in);

  return packet;
}

void PublicKeyPacket::write_body(std::ostream& out) const {
  if (m_public_key) m_public_key->write(out);
}

std::unique_ptr<PublicSubkeyPacket> PublicSubkeyPacket::create(
    ParserInput& in) {
  try {
    return PublicSubkeyPacket::create_or_throw(in);
  } catch (const pegtl::parse_error&) {
    return nullptr;
  }
}

std::unique_ptr<PublicSubkeyPacket> PublicSubkeyPacket::create_or_throw(
    ParserInput& in) {
  PublicKeyVersion version;
  pegtl::parse<public_key_packet::version, public_key_packet::action>(
      in.m_impl->m_input, version);

  auto packet = make_unique<PublicSubkeyPacket>(version);
  packet->m_public_key = PublicKeyData::create_or_throw(packet->m_version, in);
  return packet;
}

void PublicSubkeyPacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_version);
  if (m_public_key) m_public_key->write(out);
}

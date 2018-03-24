// OpenPGP public key packet (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

std::unique_ptr<PublicKeyPacket> PublicKeyPacket::create(ParserInput& in) {
  try {
    return PublicKeyPacket::create_or_throw(in);
  } catch (const pegtl::parse_error&) {
    return nullptr;
  }
}

std::unique_ptr<PublicKeyPacket> PublicKeyPacket::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<PublicKeyPacket>();
  packet->m_public_key = PublicKeyData::create_or_throw(in);
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
  auto packet = make_unique<PublicSubkeyPacket>();
  packet->m_public_key = PublicKeyData::create_or_throw(in);
  return packet;
}

void PublicSubkeyPacket::write_body(std::ostream& out) const {
  if (m_public_key) m_public_key->write(out);
}

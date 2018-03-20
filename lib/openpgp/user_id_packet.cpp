// OpenPGP user ID packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/user_id_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

std::unique_ptr<UserIdPacket> UserIdPacket::create(ParserInput& in) {
  try {
    return UserIdPacket::create_or_throw(in);
  } catch (const pegtl::parse_error&) {
    return nullptr;
  }
}

std::unique_ptr<UserIdPacket> UserIdPacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<UserIdPacket>();
  packet->m_content.assign(in.current(), in.size());
  in.bump(in.size());
  return packet;
}

void UserIdPacket::write_body(std::ostream& out) const {
  out.write(m_content.data(), m_content.size());
}

PacketType UserIdPacket::type() const { return PacketType::UserId; }

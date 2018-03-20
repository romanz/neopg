// OpenPGP trust packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/packet_header.h>
#include <neopg/trust_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

std::unique_ptr<TrustPacket> TrustPacket::create(ParserInput& in) {
  try {
    return TrustPacket::create_or_throw(in);
  } catch (const pegtl::parse_error&) {
    return nullptr;
  }
}

std::unique_ptr<TrustPacket> TrustPacket::create_or_throw(ParserInput& in) {
  auto ptr = (const uint8_t*)in.current();
  auto packet = NeoPG::make_unique<TrustPacket>();
  packet->m_data.assign(ptr, ptr + in.size());
  in.bump(in.size());
  return packet;
}

void TrustPacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_data.data()), m_data.size());
}

PacketType TrustPacket::type() const { return PacketType::Trust; }

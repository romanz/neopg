// OpenPGP packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/packet.h>

#include <neopg/marker_packet.h>
#include <neopg/public_key_packet.h>
#include <neopg/raw_packet.h>
#include <neopg/user_id_packet.h>

#include <neopg/parser_input.h>
#include <neopg/stream.h>

#include <neopg/intern/cplusplus.h>

using namespace NeoPG;

std::unique_ptr<Packet> Packet::create_or_throw(PacketType type,
                                                ParserInput& in) {
  switch (type) {
    case PacketType::Marker:
      return MarkerPacket::create_or_throw(in);
    case PacketType::UserId:
      return UserIdPacket::create_or_throw(in);
    case PacketType::PublicKey:
      return PublicKeyPacket::create_or_throw(in);
    default:
      // Should we do this?
      return NeoPG::make_unique<RawPacket>(
          type, std::string(in.current(), in.size()));
  }
}

void Packet::write(std::ostream& out) const {
  if (m_header) {
    m_header->write(out);
  } else {
    CountingStream cnt;
    write_body(cnt);
    uint32_t len = cnt.bytes_written();
    NewPacketHeader default_header(type(), len);
    default_header.write(out);
  }
  write_body(out);
}

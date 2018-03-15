// OpenPGP format
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/packet.h>

#include <neopg/marker_packet.h>
#include <neopg/raw_packet.h>
#include <neopg/user_id_packet.h>

#include <neopg/stream.h>

#include <neopg/intern/cplusplus.h>

using namespace NeoPG;

std::unique_ptr<Packet> Packet::create(PacketType type, const char* data,
                                       size_t len) {
  switch (type) {
    case PacketType::Marker:
      return NeoPG::make_unique<MarkerPacket>(data, len);
    case PacketType::UserId:
      return NeoPG::make_unique<UserIdPacket>(data, len);
    default:
      // Should we do this?
      return NeoPG::make_unique<RawPacket>(type, std::string(data, len));
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

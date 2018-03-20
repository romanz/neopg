// OpenPGP marker packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/marker_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace marker_packet {
using namespace pegtl;

struct grammar : must<TAO_PEGTL_STRING("PGP"), eof> {};

}  // namespace marker_packet
}  // namespace NeoPG

std::unique_ptr<MarkerPacket> MarkerPacket::create(ParserInput& in) {
  try {
    return MarkerPacket::create_or_throw(in);
  } catch (const pegtl::parse_error&) {
    return nullptr;
  }
}

std::unique_ptr<MarkerPacket> MarkerPacket::create_or_throw(ParserInput& in) {
  pegtl::parse<marker_packet::grammar>(in.m_impl->m_input);
  return NeoPG::make_unique<MarkerPacket>();
}

void MarkerPacket::write_body(std::ostream& out) const { out << "PGP"; }

PacketType MarkerPacket::type() const { return PacketType::Marker; }

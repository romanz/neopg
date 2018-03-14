// OpenPGP marker packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/marker_packet.h>

#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace marker_packet {
using namespace pegtl;

struct grammar : must<TAO_PEGTL_STRING("PGP"), eof> {};

}  // namespace marker_packet
}  // namespace NeoPG

void MarkerPacket::write_body(std::ostream& out) const { out << "PGP"; }

PacketType MarkerPacket::type() const { return PacketType::Marker; }

MarkerPacket::MarkerPacket(const char* data, size_t len) {
  pegtl::memory_input<> in{data, len, "MarkerPacket"};
  pegtl::parse<marker_packet::grammar>(in);
}

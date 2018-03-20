// OpenPGP MDC packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/modification_detection_code_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace modification_detection_code {
using namespace pegtl;

struct mdc : bytes<20> {};

struct grammar : must<mdc, eof> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<mdc> {
  template <typename Input>
  static void apply(const Input& in, ModificationDetectionCodePacket* packet) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    packet->m_data.assign(begin, begin + in.size());
  }
};

}  // namespace modification_detection_code
}  // namespace NeoPG

std::unique_ptr<ModificationDetectionCodePacket>
ModificationDetectionCodePacket::create(ParserInput& in) {
  try {
    return ModificationDetectionCodePacket::create_or_throw(in);
  } catch (const pegtl::parse_error&) {
    return nullptr;
  }
}

std::unique_ptr<ModificationDetectionCodePacket>
ModificationDetectionCodePacket::create_or_throw(ParserInput& in) {
  auto packet = NeoPG::make_unique<ModificationDetectionCodePacket>();

  pegtl::parse<modification_detection_code::grammar,
               modification_detection_code::action>(in.m_impl->m_input,
                                                    packet.get());
  return packet;
}

void ModificationDetectionCodePacket::write_body(std::ostream& out) const {
  if (m_data.size() != 20) {
    throw std::logic_error("modification detection code has wrong size");
  }

  out.write((char*)m_data.data(), m_data.size());
}

PacketType ModificationDetectionCodePacket::type() const {
  return PacketType::ModificationDetectionCode;
}

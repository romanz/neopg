// OpenPGP trust packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>
#include <vector>

namespace NeoPG {

class NEOPG_UNSTABLE_API TrustPacket : public Packet {
 public:
  std::vector<uint8_t> m_data;

  void write_body(std::ostream& out) const override;
  PacketType type() const override;

  TrustPacket() = default;
  TrustPacket(const char* data, size_t len) {
    auto ptr = (const uint8_t*)data;
    m_data.assign(ptr, ptr + len);
  };
};

}  // namespace NeoPG

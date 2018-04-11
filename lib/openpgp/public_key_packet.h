// OpenPGP public key packet
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>
#include <neopg/public_key_data.h>

#include <memory>

namespace NeoPG {

/// Represent an OpenPGP [public-key
/// packet](https://tools.ietf.org/html/rfc4880#section-5.5.2).
class NEOPG_UNSTABLE_API PublicKeyPacket : public Packet {
 public:
  static std::unique_ptr<PublicKeyPacket> create_or_throw(ParserInput& input);
  static std::unique_ptr<PublicKeyPacket> create(ParserInput& input);

  PublicKeyVersion m_version;
  std::unique_ptr<PublicKeyData> m_public_key;

  void write_body(std::ostream& out) const override;
  PacketType type() const override { return PacketType::PublicKey; };

  PublicKeyVersion version() const noexcept { return m_version; }

  PublicKeyPacket(PublicKeyVersion version) : m_version{version} {};
};

class NEOPG_UNSTABLE_API PublicSubkeyPacket : public Packet {
 public:
  static std::unique_ptr<PublicSubkeyPacket> create_or_throw(
      ParserInput& input);
  static std::unique_ptr<PublicSubkeyPacket> create(ParserInput& input);

  PublicKeyVersion m_version;
  std::unique_ptr<PublicKeyData> m_public_key;

  void write_body(std::ostream& out) const override;
  PacketType type() const override { return PacketType::PublicSubkey; };

  PublicKeyVersion version() const noexcept { return m_version; }

  PublicSubkeyPacket(PublicKeyVersion version) : m_version{version} {};
};

}  // namespace NeoPG

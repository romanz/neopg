// OpenPGP public key packet
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>
#include <neopg/public_key_material.h>

#include <memory>

namespace NeoPG {

/// Represent an OpenPGP [public-key
/// packet](https://tools.ietf.org/html/rfc4880#section-5.5.2).
class NEOPG_UNSTABLE_API PublicKeyPacket : public Packet {
 public:
  enum class Version : uint8_t { V2 = 2, V3 = 3, V4 = 4 };

  static std::unique_ptr<PublicKeyPacket> create_or_throw(ParserInput& input);
  static std::unique_ptr<PublicKeyPacket> create(ParserInput& input);

  virtual Version version() const noexcept = 0;

  PacketType type() const override { return PacketType::PublicKey; };
};

class NEOPG_UNSTABLE_API V2o3PublicKeyPacket : public PublicKeyPacket {
 public:
  // V2 and V3 keys are identical but for the version number.
  Version m_version;

  uint32_t m_created{0};
  uint16_t m_days_valid{0};
  PublicKeyAlgorithm m_algorithm{PublicKeyAlgorithm::Rsa};
  std::unique_ptr<PublicKeyMaterial> m_key;

  static std::unique_ptr<V2o3PublicKeyPacket> create_or_throw(
      Version version, ParserInput& input);

  void write_body(std::ostream& out) const override;

  Version version() const noexcept override { return m_version; }
  V2o3PublicKeyPacket(Version version) : m_version{version} {};
};

class NEOPG_UNSTABLE_API V4PublicKeyPacket : public PublicKeyPacket {
 public:
  uint32_t m_created{0};
  PublicKeyAlgorithm m_algorithm{PublicKeyAlgorithm::Rsa};
  std::unique_ptr<PublicKeyMaterial> m_key;

  static std::unique_ptr<V4PublicKeyPacket> create_or_throw(ParserInput& input);

  void write_body(std::ostream& out) const override;
  Version version() const noexcept override { return Version::V4; }
};

}  // namespace NeoPG

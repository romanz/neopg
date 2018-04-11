// OpenPGP public key packet data
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>
#include <neopg/public_key_material.h>

#include <memory>

namespace NeoPG {

enum class PublicKeyVersion : uint8_t { V2 = 2, V3 = 3, V4 = 4 };

/// Represent an OpenPGP [public-key
/// packet](https://tools.ietf.org/html/rfc4880#section-5.5.2).
class NEOPG_UNSTABLE_API PublicKeyData {
 public:
  static std::unique_ptr<PublicKeyData> create_or_throw(
      PublicKeyVersion version, ParserInput& input);

  virtual void write(std::ostream& out) const = 0;
  virtual PublicKeyVersion version() const noexcept = 0;

  virtual std::vector<uint8_t> fingerprint() const = 0;
  virtual std::vector<uint8_t> keyid() const = 0;
};

class NEOPG_UNSTABLE_API V2o3PublicKeyData : public PublicKeyData {
 public:
  // V2 and V3 keys are identical but for the version number.
  PublicKeyVersion m_version;

  uint32_t m_created{0};
  uint16_t m_days_valid{0};
  PublicKeyAlgorithm m_algorithm{PublicKeyAlgorithm::Rsa};
  std::unique_ptr<PublicKeyMaterial> m_key;

  static std::unique_ptr<V2o3PublicKeyData> create_or_throw(
      PublicKeyVersion version, ParserInput& input);

  void write(std::ostream& out) const override;

  PublicKeyVersion version() const noexcept override { return m_version; }
  V2o3PublicKeyData(PublicKeyVersion version) : m_version{version} {};
  std::vector<uint8_t> fingerprint() const override;
  std::vector<uint8_t> keyid() const override;
};

class NEOPG_UNSTABLE_API V4PublicKeyData : public PublicKeyData {
 public:
  uint32_t m_created{0};
  PublicKeyAlgorithm m_algorithm{PublicKeyAlgorithm::Rsa};
  std::unique_ptr<PublicKeyMaterial> m_key;

  static std::unique_ptr<V4PublicKeyData> create_or_throw(ParserInput& input);

  void write(std::ostream& out) const override;
  PublicKeyVersion version() const noexcept override {
    return PublicKeyVersion::V4;
  }
  std::vector<uint8_t> fingerprint() const override;
  std::vector<uint8_t> keyid() const override;
};

}  // namespace NeoPG

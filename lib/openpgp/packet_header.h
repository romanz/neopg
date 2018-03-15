// OpenPGP format
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/common.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>

namespace NeoPG {

enum class NEOPG_UNSTABLE_API PacketType : uint8_t {
  Reserved = 0,
  PublicKeyEncryptedSessionKey = 1,
  Signature = 2,
  SymmetricKeyEncryptedSessionKey = 3,
  OnePassSignature = 4,
  SecretKey = 5,
  PublicKey = 6,
  SecretSubkey = 7,
  CompressedData = 8,
  SymmetricallyEncryptedData = 9,
  Marker = 10,
  LiteralData = 11,
  Trust = 12,
  UserId = 13,
  PublicSubkey = 14,
  UserAttribute = 17,
  SymmetricallyEncryptedIntegrityProtectedData = 18,
  ModificationDetectionCode = 19,
  Private_60 = 60,
  Private_61 = 61,
  Private_62 = 62,
  Private_63 = 63,
};

enum class NEOPG_UNSTABLE_API PacketLengthType : uint8_t {
  OneOctet = 0,
  TwoOctet = 1,

  // New packet format
  FiveOctet = 2,
  Partial = 3,

  // Old packet format
  FourOctet = 2,
  Indeterminate = 3,

  /// This picks the best encoding automatically.
  Default
};

struct NEOPG_UNSTABLE_API PacketHeader {
 public:
  size_t m_offset;

  virtual void write(std::ostream& out) = 0;
  virtual PacketType type() = 0;
};

class NEOPG_UNSTABLE_API OldPacketHeader : public PacketHeader {
 public:
  PacketType m_packet_type;
  PacketLengthType m_length_type;
  uint32_t m_length;

  static void verify_length(uint32_t length, PacketLengthType length_type);

  static PacketLengthType best_length_type(uint32_t length);

  OldPacketHeader(PacketType packet_type, uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default);

  void set_packet_type(PacketType packet_type);

  void set_length(uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default);

  void write(std::ostream& out) override;

  PacketType type() override { return m_packet_type; }
};

class NEOPG_UNSTABLE_API NewPacketTag {
 public:
  PacketType m_packet_type;

  void set_packet_type(PacketType packet_type);

  NewPacketTag(PacketType packet_type);

  void write(std::ostream& out);
};

class NEOPG_UNSTABLE_API NewPacketLength {
 public:
  PacketLengthType m_length_type;
  uint32_t m_length;

  static void verify_length(uint32_t length, PacketLengthType length_type);

  static PacketLengthType best_length_type(uint32_t length);

  void set_length(uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default);

  NewPacketLength(uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default);

  void write(std::ostream& out);
};

class NEOPG_UNSTABLE_API NewPacketHeader : public PacketHeader {
 public:
  NewPacketTag m_tag;
  NewPacketLength m_length;

  NewPacketHeader(NewPacketTag tag, NewPacketLength length)
      : m_tag(tag), m_length(length) {}

  NewPacketHeader(PacketType packet_type, uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default)
      : m_tag(packet_type), m_length(length, length_type) {}

  void write(std::ostream& out) override;

  PacketType type() override { return m_tag.m_packet_type; }
};

}  // namespace NeoPG

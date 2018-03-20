// OpenPGP public key packet (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

// We use this to test packet headers.
class MockPublicKeyPacket : public PublicKeyPacket {
  void write_body(std::ostream& out) const override{};

  Version version() const noexcept override { return Version::V2; }
};

TEST(NeoPGTest, openpgp_public_key_packet_test) {
  {
    // Test old packet header.
    std::stringstream out;
    MockPublicKeyPacket packet;
    OldPacketHeader* header = new OldPacketHeader(PacketType::PublicKey, 0);

    packet.m_header = std::unique_ptr<PacketHeader>(header);
    packet.write(out);
    // Not really a packet, but good enough for testing.
    ASSERT_EQ(out.str(), std::string("\x98\x00", 2));
  }

  {
    // Test new packet header.
    std::stringstream out;
    MockPublicKeyPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xc6\x00", 2));
  }

  {
    // Test V3 packets.
    const std::string raw{
        "\x03"
        "\x12\x34\x56\x78"
        "\xab\xcd"
        "\x01"
        "\x00\x11\x01\x42\x23"
        "\x00\x02\x03",
        16};
    ParserInput in(raw.data(), raw.length());
    auto key = PublicKeyPacket::create_or_throw(in);
    ASSERT_EQ(key->version(), PublicKeyPacket::Version::V3);
    auto v3key = dynamic_cast<V2o3PublicKeyPacket*>(key.get());
    ASSERT_EQ(v3key->m_created, 0x12345678);
    ASSERT_EQ(v3key->m_days_valid, 0xabcd);
    ASSERT_EQ(v3key->m_algorithm, PublicKeyAlgorithm::Rsa);
    ASSERT_NE(v3key->m_key, nullptr);
    ASSERT_EQ(v3key->m_key->algorithm(), PublicKeyAlgorithm::Rsa);
    auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(v3key->m_key.get());
    ASSERT_EQ(rsa->m_n, MultiprecisionInteger(0x14223));
    ASSERT_EQ(rsa->m_e, MultiprecisionInteger(0x3));
  }
}

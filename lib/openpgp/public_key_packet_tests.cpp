// OpenPGP public key packet (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeoPGTest, openpgp_public_key_packet_test) {
  {
    // Test old packet header.
    std::stringstream out;
    PublicKeyPacket packet;
    OldPacketHeader* header = new OldPacketHeader(PacketType::PublicKey, 0);

    packet.m_header = std::unique_ptr<PacketHeader>(header);
    packet.write(out);
    // Not really a packet, but good enough for testing.
    ASSERT_EQ(out.str(), std::string("\x98\x00", 2));
  }

  {
    // Test new packet header.
    std::stringstream out;
    PublicKeyPacket packet;
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
    auto packet = PublicKeyPacket::create_or_throw(in);
    auto public_key = packet->m_public_key.get();
    ASSERT_NE(public_key, nullptr);
    ASSERT_EQ(public_key->version(), PublicKeyData::Version::V3);
  }
}

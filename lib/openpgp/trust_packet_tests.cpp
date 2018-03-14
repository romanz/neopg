// Trust packet tests
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/trust_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeoPGTest, openpg_trust_packet_test) {
  {
    std::stringstream out;
    TrustPacket packet;
    packet.m_data =
        std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCC\x08"
                                     "\x01\x02\x03\x04\x05\x06\x07\x08",
                                     10));
  }

  {
    // Test parser.
    const auto trust = std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04};
    ASSERT_NO_THROW(TrustPacket((const char*)trust.data(), trust.size()));

    auto packet = TrustPacket{(const char*)trust.data(), trust.size()};
    ASSERT_EQ(packet.m_data, trust);

    // Will never throw, so no failure tests.
  }
}

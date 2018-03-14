// OpenPGP user ID packet (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/user_id_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeoPGTest, openpg_user_id_packet_test) {
  {
    // Test old packet header.
    std::stringstream out;
    UserIdPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCD\0", 2));
  }

  {
    // Test new packet header.
    std::stringstream out;
    UserIdPacket packet;
    packet.m_content = "John Doe john.doe@example.com";
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCD\x1D"
                                     "John Doe john.doe@example.com",
                                     2 + packet.m_content.size()));
  }

  {
    // Test parser.
    const auto uid = std::string{"jonny@example.com"};
    ASSERT_NO_THROW(UserIdPacket(uid.data(), uid.length()));

    auto packet = UserIdPacket(uid.data(), uid.length());
    ASSERT_EQ(packet.m_content, uid);

    // Will never throw, so no failure tests.
  }
}

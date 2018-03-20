// OpenPGP marker packet (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/marker_packet.h>

#include <neopg/intern/cplusplus.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeoPGTest, openpgp_marker_packet_test) {
  {
    // Test old packet header.
    std::stringstream out;
    MarkerPacket packet;

    packet.m_header =
        NeoPG::make_unique<OldPacketHeader>(PacketType::Marker, 3);
    packet.write(out);
    ASSERT_EQ(out.str(), "\xa8\x03PGP");
  }

  {
    // Test new packet header.
    std::stringstream out;
    MarkerPacket packet;

    packet.write(out);
    ASSERT_EQ(out.str(), "\xca\x03PGP");
  }

  {
    // Test parser (good).
    ParserInput in("PGP", 3);
    {
      ParserInput::Mark mark(in);
      ASSERT_NO_THROW(MarkerPacket::create_or_throw(in));
      ASSERT_EQ(in.position(), 3);
    }
    ASSERT_EQ(in.position(), 0);
    {
      ParserInput::Mark mark(in);
      ASSERT_NE(MarkerPacket::create(in), nullptr);
      ASSERT_EQ(in.position(), 3);
    }
  }

  {
    // Test parser error (no EOF).
    ParserInput in("PGPx", 4);
    {
      ParserInput::Mark mark(in);
      ASSERT_ANY_THROW(MarkerPacket::create_or_throw(in));
      ASSERT_EQ(in.position(), 3);
    }
    ASSERT_EQ(in.position(), 0);
    {
      ParserInput::Mark mark(in);
      ASSERT_EQ(MarkerPacket::create(in), nullptr);
      ASSERT_EQ(in.position(), 3);
    }
  }

  {
    // Test parser error (short input).
    ParserInput in("PGP", 2);
    ASSERT_ANY_THROW(MarkerPacket::create_or_throw(in));
    ASSERT_EQ(in.position(), 0);

    ASSERT_EQ(MarkerPacket::create(in), nullptr);
  }

  {
    // Test parser error (wrong input).
    ParserInput in("GPG", 3);
    ASSERT_ANY_THROW(MarkerPacket::create_or_throw(in));
    ASSERT_EQ(in.position(), 0);

    ASSERT_EQ(MarkerPacket::create(in), nullptr);
  }
}

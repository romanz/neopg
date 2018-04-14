// OpenPGP public key packet data (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_data.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeoPGTest, openpgp_public_key_data_test) {
  {
    // Test V3 packets.
    const std::string raw{
        "\x12\x34\x56\x78"
        "\xab\xcd"
        "\x01"
        "\x00\x11\x01\x42\x23"
        "\x00\x02\x03",
        15};
    const std::string fpr{
        "\xb5\xb5\xbe\xc2\x3d\x70\xea\x0e\x05\x68\x45\x64\xac\xa7\x3d\xc7"};
    ParserInput in(raw.data(), raw.length());
    auto key = PublicKeyData::create_or_throw(PublicKeyVersion::V3, in);
    ASSERT_EQ(key->version(), PublicKeyVersion::V3);
    auto v3key = dynamic_cast<V2o3PublicKeyData*>(key.get());
    ASSERT_NE(v3key, nullptr);
    ASSERT_EQ(v3key->m_created, 0x12345678);
    ASSERT_EQ(v3key->m_days_valid, 0xabcd);
    ASSERT_EQ(v3key->m_algorithm, PublicKeyAlgorithm::Rsa);
    ASSERT_NE(v3key->m_key, nullptr);
    ASSERT_EQ(v3key->m_key->algorithm(), PublicKeyAlgorithm::Rsa);
    ASSERT_EQ(reinterpret_cast<char*>(v3key->fingerprint().data()), fpr);
    auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(v3key->m_key.get());
    ASSERT_EQ(rsa->m_n, MultiprecisionInteger(0x14223));
    ASSERT_EQ(rsa->m_e, MultiprecisionInteger(0x3));
  }
  // FIXME: More tests (writing packet).
}

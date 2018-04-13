// OpenPGP signature data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/signature_data.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <botan/hash.h>

#include <algorithm>
#include <iterator>

using namespace NeoPG;

namespace NeoPG {
namespace signature_data {
using namespace pegtl;

struct v3_hashed : must<one<0x05>> {};

struct type : must<any> {};

struct created : must<bytes<4>> {};

struct signer : must<bytes<8>> {};

struct quick : must<bytes<2>> {};

struct public_key_algorithm : must<any> {};

struct hash_algorithm : must<any> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<type> {
  template <typename Input>
  static void apply(const Input& in, SignatureType& type) {
    type = static_cast<SignatureType>(in.peek_byte());
  }
};

template <>
struct action<created> {
  template <typename Input>
  static void apply(const Input& in, uint32_t& created) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    auto val2 = (uint32_t)in.peek_byte(2);
    auto val3 = (uint32_t)in.peek_byte(3);
    created = (val0 << 24) + (val1 << 16) + (val2 << 8) + val3;
  }
};

template <>
struct action<signer> {
  template <typename Input>
  static void apply(const Input& in, std::array<uint8_t, 8>& signer) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    std::copy_n(begin, in.size(), std::begin(signer));
  }
};

template <>
struct action<public_key_algorithm> {
  template <typename Input>
  static void apply(const Input& in, PublicKeyAlgorithm& algorithm) {
    algorithm = static_cast<PublicKeyAlgorithm>(in.peek_byte());
  }
};

template <>
struct action<hash_algorithm> {
  template <typename Input>
  static void apply(const Input& in, HashAlgorithm& algorithm) {
    algorithm = static_cast<HashAlgorithm>(in.peek_byte());
  }
};

template <>
struct action<quick> {
  template <typename Input>
  static void apply(const Input& in, std::array<uint8_t, 2>& quick) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    std::copy_n(begin, in.size(), std::begin(quick));
  }
};

}  // namespace signature_data
}  // namespace NeoPG

std::unique_ptr<SignatureData> SignatureData::create_or_throw(
    SignatureVersion version, ParserInput& in) {
  std::unique_ptr<SignatureData> signature;
  switch (version) {
    case SignatureVersion::V3:
      signature = V3SignatureData::create_or_throw(in);
      break;
    case SignatureVersion::V4:
      signature = V4SignatureData::create_or_throw(in);
      break;
    default:
      in.error("unknown signature version");
  }
  // if (in.size() != 0) in.error("trailing data in signature");

  return signature;
}

std::unique_ptr<V3SignatureData> V3SignatureData::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<V3SignatureData>();
  // Not very elegant, but makes it easier to reuse the same actions.
  pegtl::parse<signature_data::v3_hashed, signature_data::action>(
      in.m_impl->m_input);
  pegtl::parse<signature_data::type, signature_data::action>(in.m_impl->m_input,
                                                             packet->m_type);
  pegtl::parse<signature_data::created, signature_data::action>(
      in.m_impl->m_input, packet->m_created);
  pegtl::parse<signature_data::signer, signature_data::action>(
      in.m_impl->m_input, packet->m_signer);
  pegtl::parse<signature_data::public_key_algorithm, signature_data::action>(
      in.m_impl->m_input, packet->m_public_key_algorithm);
  pegtl::parse<signature_data::hash_algorithm, signature_data::action>(
      in.m_impl->m_input, packet->m_hash_algorithm);
  pegtl::parse<signature_data::quick, signature_data::action>(
      in.m_impl->m_input, packet->m_quick);

  // packet->m_signature =
  // SignatureMaterial::create_or_throw(packet->m_public_key_algorithm, in);
#if 0
  switch (packet->m_public_key_algorithm) {
    case PublicKeyAlgorithm::Rsa:
    case PublicKeyAlgorithm::RsaEncrypt:
    case PublicKeyAlgorithm::RsaSign:
      break;
    default:
      in.error("unknown v3 signature algorithm");
  }
#endif

  return packet;
}

void V3SignatureData::write(std::ostream& out) const {
  out << static_cast<uint8_t>(0x05);
  out << static_cast<uint8_t>(m_type);
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
  std::copy(std::begin(m_signer), std::end(m_signer),
            std::ostream_iterator<uint8_t>(out));
  out << static_cast<uint8_t>(m_public_key_algorithm);
  out << static_cast<uint8_t>(m_hash_algorithm);
  std::copy(std::begin(m_quick), std::end(m_quick),
            std::ostream_iterator<uint8_t>(out));
  // FIXME: Really optional?  (Useful for testing)
  // if (m_key) m_key->write(out);
}

std::unique_ptr<V4SignatureData> V4SignatureData::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<V4SignatureData>();

  pegtl::parse<signature_data::type, signature_data::action>(in.m_impl->m_input,
                                                             packet->m_type);
  pegtl::parse<signature_data::public_key_algorithm, signature_data::action>(
      in.m_impl->m_input, packet->m_public_key_algorithm);
  pegtl::parse<signature_data::hash_algorithm, signature_data::action>(
      in.m_impl->m_input, packet->m_hash_algorithm);
  // hashed
  // unhashed
  pegtl::parse<signature_data::quick, signature_data::action>(
      in.m_impl->m_input, packet->m_quick);

  // packet->m_signature =
  // SignatureMaterial::create_or_throw(packet->m_public_key_algorithm, in);
#if 0
  switch (packet->m_public_key_algorithm) {
    case PublicKeyAlgorithm::Rsa:
    case PublicKeyAlgorithm::RsaEncrypt:
    case PublicKeyAlgorithm::RsaSign:
      break;
    default:
      in.error("unknown v4 signature algorithm");
  }
#endif

  return packet;
}

void V4SignatureData::write(std::ostream& out) const {}

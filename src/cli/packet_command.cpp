/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg-tool/command.h>
#include <neopg-tool/packet_command.h>

#include <neopg/marker_packet.h>
#include <neopg/openpgp.h>
#include <neopg/public_key_packet.h>
#include <neopg/raw_packet.h>
#include <neopg/stream.h>
#include <neopg/user_id_packet.h>

#include <botan/data_snk.h>
#include <botan/data_src.h>

#include <CLI11.hpp>

#include <json.hpp>
using json = nlohmann::json;

#include <boost/format.hpp>

#include <iostream>

namespace NeoPG {

void MarkerPacketCommand::run() {
  MarkerPacket packet;
  packet.write(std::cout);
}

void UserIdPacketCommand::run() {
  UserIdPacket packet;
  packet.m_content = m_uid;
  packet.write(std::cout);
}

struct LegacyPacketSink : public RawPacketSink {
  void next_packet(std::unique_ptr<PacketHeader> header, const char* data,
                   size_t length) {
    // # off=0 ctb=99 tag=6 hlen=3 plen=525
    // # off=229725 ctb=d1 tag=17 hlen=6 plen=3033 new-ctb

    // FIXME: Use fmt library instead of boost, expand PacketHeader API.
    std::stringstream head_ss;
    header->write(head_ss);
    auto head = head_ss.str();

    auto new_header = dynamic_cast<NewPacketHeader*>(header.get());

    std::cout << "# off=" << header->m_offset
              << " ctb=" << (boost::format("%02x") % (int)(uint8_t)head[0])
              << " tag=" << (int)header->type() << " hlen=" << head.length()
              << " plen=" << length << (new_header ? " new-ctb" : "") << "\n";

    // FIXME: Catch exception in nested parsing, show useful debug output,
    // default to raw.
    ParserInput in{data, length};
    auto packet = Packet::create_or_throw(header->type(), in);
    packet->m_header = std::move(header);
    switch (packet->type()) {
      case PacketType::Marker:
        std::cout << ":marker packet: PGP\n";
        break;
      case PacketType::UserId: {
        auto uid = dynamic_cast<UserIdPacket*>(packet.get());
        assert(uid);
        json str = uid->m_content;
        std::cout << ":user ID packet: " << str << "\n";
      } break;
      case PacketType::PublicKey: {
        PublicKeyMaterial* key = nullptr;
        auto pub = dynamic_cast<PublicKeyPacket*>(packet.get());
        assert(pub);
        std::cout << ":public key packet:\n";
        switch (pub->version()) {
          case PublicKeyPacket::Version::V2:
          case PublicKeyPacket::Version::V3: {
            auto v3pub = dynamic_cast<V2o3PublicKeyPacket*>(pub);
            std::cout << "\tversion " << static_cast<int>(pub->version())
                      << ", algo " << static_cast<int>(v3pub->m_algorithm)
                      << ", created " << v3pub->m_created << ", expires "
                      << v3pub->m_days_valid << "\n";
            key = v3pub->m_key.get();
          } break;
          case PublicKeyPacket::Version::V4: {
            auto v4pub = dynamic_cast<V4PublicKeyPacket*>(pub);
            std::cout << "\tversion " << static_cast<int>(pub->version())
                      << ", algo " << static_cast<int>(v4pub->m_algorithm)
                      << ", created " << v4pub->m_created << ", expires 0"
                      << "\n";
            key = v4pub->m_key.get();
          } break;
          default:
            std::cout << "\tversion " << static_cast<int>(pub->version())
                      << "\n";
            break;
        }
        if (key) {
          switch (key->algorithm()) {
            case PublicKeyAlgorithm::Rsa: {
              auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(key);
              std::cout << "\tpkey[0]: [" << rsa->m_n.length() << " bits]\n";
              std::cout << "\tpkey[1]: [" << rsa->m_e.length() << " bits]\n";
            } break;
            case PublicKeyAlgorithm::Dsa: {
              auto dsa = dynamic_cast<DsaPublicKeyMaterial*>(key);
              std::cout << "\tpkey[0]: [" << dsa->m_p.length() << " bits]\n";
              std::cout << "\tpkey[1]: [" << dsa->m_q.length() << " bits]\n";
              std::cout << "\tpkey[2]: [" << dsa->m_g.length() << " bits]\n";
              std::cout << "\tpkey[3]: [" << dsa->m_y.length() << " bits]\n";
            } break;
            case PublicKeyAlgorithm::Elgamal: {
              auto elgamal = dynamic_cast<ElgamalPublicKeyMaterial*>(key);
              std::cout << "\tpkey[0]: [" << elgamal->m_p.length()
                        << " bits]\n";
              std::cout << "\tpkey[1]: [" << elgamal->m_g.length()
                        << " bits]\n";
              std::cout << "\tpkey[2]: [" << elgamal->m_y.length()
                        << " bits]\n";
            } break;
          }
        }
      } break;
      default:
        break;
    }
  }
  void start_packet(std::unique_ptr<PacketHeader> header){};
  void continue_packet(const char* data, size_t length){};
  void finish_packet(std::unique_ptr<NewPacketLength> length_info,
                     const char* data, size_t length){};
};

static void process_msg(Botan::DataSource& source, Botan::DataSink& out) {
  out.start_msg();
  LegacyPacketSink sink;
  RawPacketParser parser(sink);
  parser.process(source);

  // Botan::secure_vector<uint8_t> buffer(Botan::DEFAULT_BUFFERSIZE);
  // while (!source.end_of_data()) {
  //   size_t got = source.read(buffer.data(), buffer.size());
  //   std::cerr << "XXX " << got << "\n";
  //   out.write(buffer.data(), got);
  // }
  out.end_msg();
}

void FilterPacketCommand::run() {
  Botan::DataSink_Stream out{std::cout};

  if (m_files.empty()) m_files.emplace_back("-");
  for (auto& file : m_files) {
    if (file == "-") {
      Botan::DataSource_Stream in{std::cin};
      process_msg(in, out);
    } else {
      // Open in binary mode.
      Botan::DataSource_Stream in{file, true};
      process_msg(in, out);
    }
  }
}

PacketCommand::PacketCommand(CLI::App& app, const std::string& flag,
                             const std::string& description,
                             const std::string& group_name)
    : Command(app, flag, description, group_name),
      cmd_marker(m_cmd, "marker", "output a Marker Packet", group_write),
      cmd_uid(m_cmd, "uid", "output a User ID Packet", group_write),
      cmd_filter(m_cmd, "filter", "process packet data", group_process) {}

void PacketCommand::run() {
  if (m_cmd.get_subcommands().empty()) throw CLI::CallForHelp();
}

}  // Namespace NeoPG

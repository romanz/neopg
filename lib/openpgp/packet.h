// OpenPGP packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet_header.h>
#include <neopg/parser_input.h>

#include <memory>

namespace NeoPG {

struct NEOPG_UNSTABLE_API Packet {
  static std::unique_ptr<Packet> create_or_throw(PacketType type,
                                                 ParserInput& in);

  /// Use this to overwrite the default header.
  // FIXME: Replace this with a header-generator that comes in different
  // flavors, see issue #66.
  std::unique_ptr<PacketHeader> m_header;

  void write(std::ostream& out) const;

  /// Write the body of the packet to \p out.
  ///
  /// @param out The output stream to which the body is written.
  virtual void write_body(std::ostream& out) const = 0;

  /// Return the packet type.
  ///
  /// \return The tag of the packet.
  virtual PacketType type() const = 0;
};

}  // namespace NeoPG

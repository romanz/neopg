/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/openpgp/packet.h>
#include <neopg/utils/stream.h>

namespace NeoPG {
namespace OpenPGP {

void Packet::write(std::ostream& out) {
  if (m_header) {
    m_header->write(out);
  } else {
    CountingStream cnt;
    write_body(cnt);
    uint32_t len = cnt.bytes_written();
    NewPacketHeader default_header(type(), len);
    default_header.write(out);
  }
  write_body(out);
}

}  // namespace OpenPGP
}  // namespace NeoPG

// OpenPGP parser
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/parser_input.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;
using namespace tao::neopg_pegtl;

ParserInput::ParserInput(const char* data, size_t length)
    : m_impl{NeoPG::make_unique<Impl>(data, length)} {}

ParserInput::~ParserInput() = default;

const char* ParserInput::current() const noexcept {
  return m_impl->m_input.current();
}

size_t ParserInput::size() { return m_impl->m_input.size(); }

size_t ParserInput::position() const { return m_impl->m_input.position().byte; }

void ParserInput::bump(const std::size_t in_count) noexcept {
  m_impl->m_input.bump(in_count);
}

void ParserInput::error(const std::string& message) {
  throw pegtl::parse_error(message, m_impl->m_input);
}

ParserInput::Mark::Mark(ParserInput& in)
    : m_impl{NeoPG::make_unique<Impl>(in)} {}
ParserInput::Mark::~Mark() = default;

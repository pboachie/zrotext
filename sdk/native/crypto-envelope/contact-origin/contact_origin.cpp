// SPDX-License-Identifier: AGPL-3.0-only
// Narrow ABI over pinned Ada. No networking or caller-owned output allocation.
#include "ada.h"
#include <cstddef>
#include <string_view>
#ifdef _WIN32
#define ZT_EXPORT extern "C" __declspec(dllexport)
#else
#define ZT_EXPORT extern "C" __attribute__((visibility("default")))
#endif
ZT_EXPORT int zrotext_contact_origin_v1(const char* bytes, std::size_t size) noexcept {
  try {
    if (!bytes || size < 9 || size > 512) return 0;
    for (std::size_t i = 0; i < size; ++i)
      if (static_cast<unsigned char>(bytes[i]) < 0x21 || static_cast<unsigned char>(bytes[i]) > 0x7e) return 0;
    std::string_view input(bytes, size);
    auto parsed = ada::parse<ada::url_aggregator>(input);
    return parsed && parsed->get_protocol() == "https:" && parsed->get_origin() == input &&
      parsed->get_username().empty() && parsed->get_password().empty() &&
      parsed->get_pathname() == "/" && parsed->get_search().empty() && parsed->get_hash().empty();
  } catch (...) { return 0; }
}

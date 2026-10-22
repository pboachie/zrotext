// SPDX-License-Identifier: AGPL-3.0-only
// Narrow ABI over pinned Ada. No networking or caller-owned output allocation.
#include "ada.h"
#include "contact_bidi16.h"
#include <cstddef>
#include <iterator>
#include <string_view>
#include <utility>
#include <vector>

enum : unsigned {Ltr=1,Rtl=2,European=4,Arabic=8,AllowRtl=16,AllowLtr=32,Nonspacing=64};

static unsigned bidi_flags(char32_t code) {
  std::size_t low=0,high=std::size(contact_bidi16_ranges);
  while(low<high){const auto middle=low+(high-low)/2;if(contact_bidi16_ranges[middle].last<code)low=middle+1;else high=middle;}
  return low<std::size(contact_bidi16_ranges)&&contact_bidi16_ranges[low].first<=code?contact_bidi16_ranges[low].flags:0;
}
static bool valid_bidi_host(std::string_view host) {
  if(host.find("xn--")==std::string_view::npos)return true;
  std::vector<std::u32string> labels;bool directional=false;
  for(std::size_t start=0;start<=host.size();){
    const auto end=host.find('.',start);
    const auto label=host.substr(start,end==std::string_view::npos?host.size()-start:end-start);
    std::u32string decoded;
    if(label.starts_with("xn--")){if(!ada::idna::punycode_to_utf32(label.substr(4),decoded))return false;}
    else decoded.assign(label.begin(),label.end());
    for(const auto code:decoded)directional|=(bidi_flags(code)&(Rtl|Arabic))!=0;
    labels.push_back(std::move(decoded));
    if(end==std::string_view::npos)break;
    start=end+1;
  }
  if(!directional)return true;
  for(const auto& label:labels){
    if(label.empty())continue;
    const bool rtl=(bidi_flags(label.front())&Rtl)!=0;
    if(!rtl&&!(bidi_flags(label.front())&Ltr))return false;
    unsigned final=0;bool european=false,arabic=false;
    for(const auto code:label){
      const auto flags=bidi_flags(code);
      if(!(flags&(rtl?AllowRtl:AllowLtr)))return false;
      if(!(flags&Nonspacing))final=flags;
      european|=(flags&European)!=0;arabic|=(flags&Arabic)!=0;
    }
    if(!(final&(rtl?(Rtl|European|Arabic):(Ltr|European)))||(rtl&&european&&arabic))return false;
  }
  return true;
}
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
      valid_bidi_host(parsed->get_hostname()) &&
      parsed->get_username().empty() && parsed->get_password().empty() &&
      parsed->get_pathname() == "/" && parsed->get_search().empty() && parsed->get_hash().empty();
  } catch (...) { return 0; }
}

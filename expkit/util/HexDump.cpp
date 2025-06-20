#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include "util/HexDump.hpp"

void HexDump::Dump(char* dst, const uint8_t* buf, int len) {
  char text[17] = {};
  for (int i = 0; i < len; i++) {
    dst += sprintf(dst, "%02X ", buf[i]);
    int o = i % 16;
    text[o] = ' ' <= buf[i] && buf[i] <= '~' ? buf[i] : '.';
    if (i == len - 1)
      dst += sprintf(dst, "%*s |  %.*s\n", 3 * (15 - o) + (o < 8 ? 1 : 0), "",
                     o + 1, text);
    else if (o == 7)
      dst += sprintf(dst, " ");
    else if (o == 15)
      dst += sprintf(dst, " |  %s\n", text);
  }
}

std::string HexDump::Dump(const void* buf, int len) {
  std::string result(((len - 1) / 16 + 1) * 70, 0);
  Dump(result.data(), (const uint8_t*)buf, len);
  return result;
}

std::string HexDump::Dump(const std::vector<uint8_t>& data) {
  return Dump(data.data(), data.size());
}

void HexDump::Print(const void* buf, int len) {
  printf("%s", Dump(buf, len).c_str());
}

void HexDump::Print(const std::vector<uint8_t>& data) {
  Print(data.data(), data.size());
}

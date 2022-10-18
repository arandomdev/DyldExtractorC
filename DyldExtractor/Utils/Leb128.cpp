#include "Leb128.h"

#include <stdexcept>

using namespace DyldExtractor;

uint64_t Utils::readUleb128(const uint8_t *&p, const uint8_t *end) {
  uint64_t result = 0;
  int bit = 0;
  do {
    if (p == end) {
      throw std::invalid_argument("malformed uleb128");
    }
    uint64_t slice = *p & 0x7f;

    if (bit > 63) {
      throw std::invalid_argument("uleb128 too big for uint64");
    } else {
      result |= (slice << bit);
      bit += 7;
    }
  } while (*p++ & 0x80);
  return result;
}

int64_t Utils::readSleb128(const uint8_t *&p, const uint8_t *end) {
  int64_t result = 0;
  int bit = 0;
  uint8_t byte = 0;
  do {
    if (p == end) {
      throw std::invalid_argument("malformed sleb128");
    }
    byte = *p++;
    result |= (((int64_t)(byte & 0x7f)) << bit);
    bit += 7;
  } while (byte & 0x80);
  // sign extend negative numbers
  if (((byte & 0x40) != 0) && (bit < 64))
    result |= (~0ULL) << bit;
  return result;
}

void Utils::appendUleb128(std::vector<uint8_t> &out, uint64_t value) {
  uint8_t byte;
  do {
    byte = value & 0x7F;
    value &= ~0x7F;
    if (value != 0)
      byte |= 0x80;
    out.push_back(byte);
    value = value >> 7;
  } while (byte >= 0x80);
}

void Utils::appendSleb128(std::vector<uint8_t> &out, int64_t value) {
  bool isNeg = (value < 0);
  uint8_t byte;
  bool more;
  do {
    byte = value & 0x7F;
    value = value >> 7;
    if (isNeg)
      more = ((value != -1) || ((byte & 0x40) == 0));
    else
      more = ((value != 0) || ((byte & 0x40) != 0));
    if (more)
      byte |= 0x80;
    out.push_back(byte);
  } while (more);
}
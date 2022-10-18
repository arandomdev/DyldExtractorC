#ifndef __UTILS_LEB128__
#define __UTILS_LEB128__

#include <stdint.h>
#include <vector>

namespace DyldExtractor::Utils {

uint64_t readUleb128(const uint8_t *&p, const uint8_t *end);
int64_t readSleb128(const uint8_t *&p, const uint8_t *end);
void appendUleb128(std::vector<uint8_t> &out, uint64_t value);
void appendSleb128(std::vector<uint8_t> &out, int64_t value);

} // namespace DyldExtractor::Utils

#endif // __UTILS_LEB128__
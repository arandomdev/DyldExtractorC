#ifndef __UTILS_ARCHITECTURES__
#define __UTILS_ARCHITECTURES__

#include <stdint.h>

namespace DyldExtractor::Utils {

namespace Arch {

class Pointer32 {
public:
  using PtrT = uint32_t;
  using SPtrT = int32_t;
};

class Pointer64 {
public:
  using PtrT = uint64_t;
  using SPtrT = int64_t;
};

struct x86_64 {
  using P = Pointer64;
};

struct arm {
  using P = Pointer32;
};

struct arm64 {
  using P = Pointer64;
};

struct arm64_32 {
  using P = Pointer32;
};

} // namespace Arch
} // namespace DyldExtractor::Utils

#endif // __UTILS_ARCHITECTURES__
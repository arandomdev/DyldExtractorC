#ifndef __UTILS_ARCHITECTURES__
#define __UTILS_ARCHITECTURES__

#include <stdint.h>

namespace Utils {

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

/// @brief Align n up to a stride k
/// @param n The number to align.
/// @param k The stride to align to.
template <class T1, class T2> inline void align(T1 *n, T2 k) {
  *n = (*n + k - 1) / k * k;
}

/// @brief Align n up to a stride k
/// @param n The number to align.
/// @param k The stride to align to.
/// @returns The aligned number.
template <class T1, class T2> inline T1 align(T1 n, T2 k) {
  return (n + k - 1) / k * k;
}

namespace Arch {

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
} // namespace Utils

#endif // __UTILS_ARCHITECTURES__
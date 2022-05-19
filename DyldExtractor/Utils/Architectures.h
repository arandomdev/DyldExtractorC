#ifndef __UTILS_ARCHITECTURES__
#define __UTILS_ARCHITECTURES__

#include <stdint.h>

namespace Utils {

class Pointer32 {
  public:
    using ptr_t = uint32_t;
};

class Pointer64 {
  public:
    using ptr_t = uint64_t;
};

/// Align n up to a stride k
///
/// @param n The number to align.
/// @param k The stride to align to.
template <class T1, class T2> inline void alignR(T1 &n, T2 k) {
    n = (n + k - 1) / k * k;
}

/// Align n up to a stride k
///
/// @param n The number to align.
/// @param k The stride to align to.
/// @returns The aligned number.
template <class T1, class T2> inline T1 align(T1 n, T2 k) {
    return (n + k - 1) / k * k;
}

namespace Arch {

struct x86_64 {
    typedef Pointer64 P;
};

struct arm {
    typedef Pointer32 P;
};

struct arm64 {
    typedef Pointer64 P;
};

struct arm64_32 {
    typedef Pointer32 P;
};

} // namespace Arch
} // namespace Utils

#endif // __UTILS_ARCHITECTURES__
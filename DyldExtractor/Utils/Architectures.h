#ifndef __UTILS_ARCHITECTURES__
#define __UTILS_ARCHITECTURES__

#include <stdint.h>

namespace Utils {

class Pointer32 {
  public:
    typedef uint32_t uint_t;

    static uint64_t getP(const uint_t &from) { return from; }
    static void setP(uint_t &into, uint64_t value) { into = (uint_t)value; }
};

class Pointer64 {
  public:
    typedef uint64_t uint_t;

    static uint64_t getP(const uint_t &from) { return from; }
    static void setP(uint_t &into, uint64_t value) { into = (uint_t)value; }
};

/// Align n to a stride k
///
/// @param n The number to align.
/// @param k The stride to align to.
template <class T1, class T2> inline void align(T1 &n, T2 k) {
    n = (n + k - 1) / k * k;
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
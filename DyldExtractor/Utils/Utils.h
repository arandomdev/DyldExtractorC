#ifndef __UTILS__UTILS__
#define __UTILS__UTILS__
#include <utility>
namespace DyldExtractor::Utils {

/// @brief Align n up to a stride k
/// @param n The number to align.
/// @param k The stride to align to.
template <class T1, class T2> inline void align(T1 *n, T2 k) {
  *n = (T1)((*n + k - 1) / k * k);
}

/// @brief Align n up to a stride k
/// @param n The number to align.
/// @param k The stride to align to.
/// @returns The aligned number.
template <class T1, class T2> inline T1 align(T1 n, T2 k) {
  return (T1)((n + k - 1) / k * k);
}

/// Mark a code path as unreachable, ported from c++23
[[noreturn]] inline void unreachable() {
#ifdef __GNUC__
  __builtin_unreachable();
#elif _MSC_VER
  __assume(false);
#endif

#ifndef NDEBUG
  abort();
#endif
}

} // namespace DyldExtractor::Utils

#endif // __UTILS__UTILS__

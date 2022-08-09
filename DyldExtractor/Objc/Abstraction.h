#ifndef __OBJC_ABSTRACTION__
#define __OBJC_ABSTRACTION__

#include <stdint.h>

namespace Objc {
namespace _Defs {

template <class P> struct class_t {
  using PtrT = P::PtrT;

  PtrT isa;        // class_t *
  PtrT superclass; // class_t *
  PtrT method_cache;
  PtrT vtable;
  PtrT data; // class_data_t *
};

} // namespace _Defs

struct image_info {
  uint32_t version;
  uint32_t flags;
};

template <class P> struct class_t : public _Defs::class_t<P> {
  constexpr static std::size_t PTRS[] = {
      offsetof(_Defs::class_t<P>, isa), offsetof(_Defs::class_t<P>, superclass),
      offsetof(_Defs::class_t<P>, method_cache),
      offsetof(_Defs::class_t<P>, vtable), offsetof(_Defs::class_t<P>, data)};
};

} // namespace Objc

#endif // __OBJC_ABSTRACTION__
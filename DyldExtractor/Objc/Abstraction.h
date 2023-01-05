#ifndef __OBJC_ABSTRACTION__
#define __OBJC_ABSTRACTION__

#include <array>
#include <stdint.h>

/// Name of segment used for extra ObjC data
#define SEG_OBJC_EXTRA "__OBJC_EXTRA"

#define RELATIVE_METHOD_MAGIC_SELECTOR "\xf0\x9f\xa4\xaf"

namespace DyldExtractor::Objc {

struct image_info {
  enum : uint32_t {
    // 1 byte assorted flags
    IsReplacement = 1 << 0,   // used for Fix&Continue, now ignored
    SupportsGC = 1 << 1,      // image supports GC
    RequiresGC = 1 << 2,      // image requires GC
    OptimizedByDyld = 1 << 3, // image is from an optimized shared cache
    SignedClassRO = 1 << 4,   // class_ro_t pointers are signed
    IsSimulated = 1 << 5,     // image compiled for a simulator platform
    HasCategoryClassProperties = 1 << 6, // class properties in category_t
    OptimizedByDyldClosure =
        1 << 7, // dyld (not the shared cache) optimized this.

    // 1 byte Swift unstable ABI version number
    SwiftUnstableVersionMaskShift = 8,
    SwiftUnstableVersionMask = 0xff << SwiftUnstableVersionMaskShift,

    // 2 byte Swift stable ABI version number
    SwiftStableVersionMaskShift = 16,
    SwiftStableVersionMask = 0xffffUL << SwiftStableVersionMaskShift
  };

  uint32_t version;
  uint32_t flags;
};

template <class P> struct class_t {
  using PtrT = P::PtrT;

  enum : PtrT {
    bitsMask = 0x3, // These bits mark a swift class in the data field
  };

  PtrT isa;        // class_t *
  PtrT superclass; // class_t *
  PtrT method_cache;
  PtrT vtable;
  PtrT data; // class_data_t *

  constexpr static std::array<std::size_t, 5> PTRS() {
    return {offsetof(class_t<P>, isa), offsetof(class_t<P>, superclass),
            offsetof(class_t<P>, method_cache), offsetof(class_t<P>, vtable),
            offsetof(class_t<P>, data)};
  }
};

template <class P> struct class_data_t {
  using PtrT = P::PtrT;

  enum : uint32_t { rootClassFlag = (1 << 1) };

  uint32_t flags;
  uint32_t instanceStart;
  // Note there is 4-bytes of alignment padding between instanceSize and
  // ivarLayout on 64-bit archs, but no padding on 32-bit archs. This union is a
  // way to model that.
  union {
    uint32_t instanceSize;
    PtrT pad;
  } instanceSize;
  PtrT ivarLayout;
  PtrT name;
  PtrT baseMethods;
  PtrT baseProtocols;
  PtrT ivars;
  PtrT weakIvarLayout;
  PtrT baseProperties;

  constexpr static std::array<std::size_t, 7> PTRS() {
    return {offsetof(class_data_t<P>, ivarLayout),
            offsetof(class_data_t<P>, name),
            offsetof(class_data_t<P>, baseMethods),
            offsetof(class_data_t<P>, baseProtocols),
            offsetof(class_data_t<P>, ivars),
            offsetof(class_data_t<P>, weakIvarLayout),
            offsetof(class_data_t<P>, baseProperties)};
  }
};

struct method_small_t {
  int32_t name;  // SEL
  int32_t types; // const char *
  int32_t imp;   // IMP

  constexpr static std::array<std::size_t, 0> PTRS() { return {}; }
};

template <class P> struct method_large_t {
  using PtrT = P::PtrT;

  PtrT name;  // SEL
  PtrT types; // const char *
  PtrT imp;   // IMP

  constexpr static std::array<std::size_t, 3> PTRS() {
    return {offsetof(method_large_t<P>, name),
            offsetof(method_large_t<P>, types),
            offsetof(method_large_t<P>, imp)};
  }
};

struct method_list_t {
  enum : uint32_t {
    // If this is set, the relative method lists name_offset field is an
    // offset directly to the SEL, not a SEL ref.
    relativeMethodSelectorsAreDirectFlag = 0x40000000,

    // If this is set, then method lists are the new relative format, not
    // the old pointer based format
    relativeMethodFlag = 0x80000000,

    // The upper 16-bits are all defined to be flags
    methodListFlagsMask = 0xFFFF0000
  };

  uint32_t entsizeAndFlags;
  uint32_t count;

  uint32_t getEntsize() const {
    return entsizeAndFlags & ~(uint32_t)3 & ~methodListFlagsMask;
  }
  bool usesRelativeMethods() const {
    return (entsizeAndFlags & relativeMethodFlag) != 0;
  }

  constexpr static std::array<std::size_t, 0> PTRS() { return {}; }
};

template <class P> struct protocol_t {
  using PtrT = P::PtrT;

  PtrT isa;
  PtrT name;
  PtrT protocols;
  PtrT instanceMethods;
  PtrT classMethods;
  PtrT optionalInstanceMethods;
  PtrT optionalClassMethods;
  PtrT instanceProperties;
  uint32_t size;
  uint32_t flags;

  /// Fields below this point are not always present on disk.
  PtrT extendedMethodTypes;
  PtrT demangledName;
  PtrT classProperties;

  bool hasExtendedMethodTypes() const {
    return size >= (offsetof(protocol_t, extendedMethodTypes) +
                    sizeof(extendedMethodTypes));
  }

  bool hasDemangledName() const {
    return size >=
           (offsetof(protocol_t, demangledName) + sizeof(demangledName));
  }

  bool hasClassProperties() const {
    return size >=
           (offsetof(protocol_t, classProperties) + sizeof(classProperties));
  }

  constexpr static std::array<std::size_t, 11> PTRS() {
    return {offsetof(protocol_t, isa),
            offsetof(protocol_t, name),
            offsetof(protocol_t, protocols),
            offsetof(protocol_t, instanceMethods),
            offsetof(protocol_t, classMethods),
            offsetof(protocol_t, optionalInstanceMethods),
            offsetof(protocol_t, optionalClassMethods),
            offsetof(protocol_t, instanceProperties),
            offsetof(protocol_t, extendedMethodTypes),
            offsetof(protocol_t, demangledName),
            offsetof(protocol_t, classProperties)};
  }
};

template <class P> struct protocol_list_t {
  using PtrT = P::PtrT;

  PtrT count;

  constexpr static std::array<std::size_t, 0> PTRS() { return {}; }
};

template <class P> struct property_t {
  using PtrT = P::PtrT;

  PtrT name;
  PtrT attributes;

  constexpr static std::array<std::size_t, 2> PTRS() {
    return {offsetof(property_t, name), offsetof(property_t, attributes)};
  }
};

struct property_list_t {
  uint32_t entsize;
  uint32_t count;

  constexpr static std::array<std::size_t, 0> PTRS() { return {}; }
};

template <class P> struct ivar_t {
  using PtrT = P::PtrT;

  PtrT offset; // uint32_t*  (uint64_t* on x86_64)
  PtrT name;   // const char*
  PtrT type;   // const char*
  uint32_t alignment_raw;
  uint32_t size;

  uint32_t alignment() const {
    if (alignment_raw == (uint32_t)-1) {
      return sizeof(PtrT);
    } else {
      return 1 << alignment_raw;
    }
  }

  constexpr static std::array<std::size_t, 3> PTRS() {
    return {offsetof(ivar_t, offset), offsetof(ivar_t, name),
            offsetof(ivar_t, type)};
  }
};

struct ivar_list_t {
  uint32_t entsize;
  uint32_t count;

  constexpr static std::array<std::size_t, 0> PTRS() { return {}; }
};

template <class P> struct category_t {
  using PtrT = P::PtrT;

  PtrT name;
  PtrT cls;
  PtrT instanceMethods;
  PtrT classMethods;
  PtrT protocols;
  PtrT instanceProperties;

  // Fields below this point are not always present on disk.
  PtrT _classProperties;

  constexpr static std::array<std::size_t, 7> PTRS() {
    return {offsetof(category_t, name),
            offsetof(category_t, cls),
            offsetof(category_t, instanceMethods),
            offsetof(category_t, classMethods),
            offsetof(category_t, protocols),
            offsetof(category_t, instanceProperties),
            offsetof(category_t, _classProperties)};
  }
};

struct objc_opt_t {
  union {
    uint32_t version;

    struct {
      uint32_t version;
      int32_t selopt_offset;
      int32_t headeropt_offset;
      int32_t clsopt_offset;
    } v12;

    struct {
      uint32_t version;
      int32_t selopt_offset;
      int32_t headeropt_offset;
      int32_t clsopt_offset;
      int32_t protocolopt_offset;
    } v13;

    struct {
      uint32_t version;
      uint32_t flags;
      int32_t selopt_offset;
      int32_t headeropt_ro_offset;
      int32_t clsopt_offset;
      int32_t protocolopt_offset;
      int32_t headeropt_rw_offset;
    } v15a;

    struct {
      uint32_t version;
      uint32_t flags;
      int32_t selopt_offset;
      int32_t headeropt_ro_offset;
      int32_t clsopt_offset;
      int32_t unused_protocolopt_offset;
      int32_t headeropt_rw_offset;
      int32_t protocolopt_offset;
    } v15b;

    struct {
      uint32_t version;
      uint32_t flags;
      int32_t selopt_offset;
      int32_t headeropt_ro_offset;
      int32_t unused_clsopt_offset;
      int32_t unused_protocolopt_offset;
      int32_t headeropt_rw_offset;
      int32_t unused_protocolopt2_offset;
      int32_t largeSharedCachesClassOffset;
      int32_t largeSharedCachesProtocolOffset;
      int64_t relativeMethodSelectorBaseAddressOffset;
    } v16;
  };
};

struct objc_headeropt_ro_t {
  uint32_t count;
  uint32_t entsize;
};

template <class P> struct objc_header_info_ro_t {
  using SPtrT = P::SPtrT;

  SPtrT mhdr_offset; // offset to mach_header or mach_header_64
  SPtrT info_offset; // offset to objc_image_info *
};

/// @brief struct for class_data_t fields that have categories pre-attached.
/// @details In iOS17, some classes have category methods, protocols, and
///   properties pre-attached to classes with a pointer list.
///   Thanks for blacktop's go-macho for RE help.
struct relative_list_list_t {
  uint32_t entsize; // Should be 8, 64bit pointer
  uint32_t count;

  constexpr static std::array<std::size_t, 0> PTRS() { return {}; }
};

/// @brief An element in relative_list_list_t
struct relative_list_t {
  uint64_t offsetAndIndex;

  /// @brief Get the offset to the list, the offset is relative to this struct.
  int64_t getOffset() const { return (int64_t)offsetAndIndex >> 0x10; };
  /// @brief Image index of where the list is. Index in DSC images.
  uint16_t getImageIndex() const { return offsetAndIndex & 0xFFFF; };

  constexpr static std::array<std::size_t, 0> PTRS() { return {}; }
};

} // namespace DyldExtractor::Objc

#endif // __OBJC_ABSTRACTION__
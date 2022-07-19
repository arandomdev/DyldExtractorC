#ifndef __PROVIDER_POINTERTRACKER__
#define __PROVIDER_POINTERTRACKER__

#include <Dyld/Context.h>
#include <map>
#include <spdlog/spdlog.h>
#include <stdint.h>
#include <vector>

namespace Utils {
template <class P> class ExtractionContext;
}; // namespace Utils

namespace Provider {

template <class P> class PointerTracker {
  using PtrT = P::PtrT;

public:
  struct TrackedPointer {
    uint8_t *loc; // Pointer to pointer in the mCtx
    PtrT target;  // The target VM address
    bool isBind;

    struct {
      uint16_t diversity;
      bool hasAddrDiv;
      uint8_t key;
    } auth;

    void setTarget(const typename P::PtrT target);
    bool operator<(const TrackedPointer &other);
  };

  struct MappingSlideInfo {
    const uint8_t *dataStart;
    const uint64_t address;
    const uint64_t size;

    const uint32_t slideInfoVersion;
    const uint8_t *slideInfo;

    bool containsAddr(const uint64_t addr) const;
    bool containsData(const uint8_t *addr) const;
  };

  PointerTracker(const Utils::ExtractionContext<P> &eCtx);

  /// Slide the pointer at the address
  ///
  /// @param address The address of the pointer.
  /// @returns The slid pointer value.
  PtrT slideP(const PtrT addr) const;

  /// Slide the struct at the address.
  ///
  /// @tparam T The type of struct.
  /// @param address The address of the struct.
  /// @returns The slid struct.
  template <class T> T slideS(const uint64_t address) const {
    T data = *(T *)dCtx.convertAddrP(address);
    for (auto const offset : T::PTRS::P) {
      *(PtrT *)((uint8_t *)&data + offset) = slideP(address + offset);
    }
    return data;
  }

  /// Add a pointer to tracking
  ///
  /// @param loc A pointer to the pointer in the mCtx.
  /// @param target The target vm address.
  /// @param authSource The address of the pointer for auth info.
  /// @returns A reference to the tracked pointer.
  TrackedPointer &trackP(uint8_t *loc, const PtrT target,
                         const uint8_t *authSource);

  const std::vector<MappingSlideInfo> &getMappings() const;

private:
  void fillMappings();

  Dyld::Context *dCtx;
  std::shared_ptr<spdlog::logger> logger;
  std::vector<MappingSlideInfo> mappings;
  std::map<uint8_t *, TrackedPointer> pointers;
};

}; // namespace Provider

#endif // __PROVIDER_POINTERTRACKER__
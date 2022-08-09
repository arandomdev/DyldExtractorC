#ifndef __PROVIDER_POINTERTRACKER__
#define __PROVIDER_POINTERTRACKER__

#include "Symbolizer.h"
#include <Dyld/Context.h>
#include <map>
#include <spdlog/spdlog.h>
#include <stdint.h>
#include <vector>

#include <stddef.h>

namespace Provider {

template <class P> class PointerTracker {
  using PtrT = P::PtrT;

public:
  struct AuthData {
    uint16_t diversity;
    bool hasAddrDiv;
    uint8_t key;
  };

  struct MappingSlideInfo {
    const uint8_t *data;
    const uint64_t address;
    const uint64_t size;

    const uint32_t slideInfoVersion;
    const uint8_t *slideInfo;

    /// @brief Check if the mapping contains the address.
    /// @param addr The address to check
    /// @return If the mapping contains the address
    bool containsAddr(const uint64_t addr) const;

    /// @brief Convert the address to a pointer
    /// @param addr The address to convert
    /// @return A pointer regardless if the mapping contains it.
    const uint8_t *convertAddr(const uint64_t addr) const;
  };

  PointerTracker(const Dyld::Context &dCtx,
                 std::shared_ptr<spdlog::logger> logger);
  PointerTracker(const PointerTracker &o) = delete;
  PointerTracker(PointerTracker &&o) = default;
  PointerTracker &operator=(const PointerTracker &o) = delete;
  PointerTracker &operator=(PointerTracker &&o) = default;
  ~PointerTracker() = default;

  /// @brief Slide the pointer at the address
  /// @param address The address of the pointer.
  /// @returns The slid pointer value.
  PtrT slideP(const PtrT addr) const;

  /// @brief Slide the struct at the address.
  /// @tparam T The type of struct.
  /// @param address The address of the struct.
  /// @returns The slid struct.
  template <class T> T slideS(const PtrT address) const {
    T data = *reinterpret_cast<const T *>(dCtx->convertAddrP(address));
    for (auto offset : T::PTRS) {
      *(PtrT *)((uint8_t *)&data + (PtrT)offset) =
          slideP(address + (PtrT)offset);
    }
    return data;
  }

  /// @brief Add a pointer to tracking, overwriting if already added.
  /// @param addr Address of the pointer.
  /// @param target The target address.
  void add(const PtrT addr, const PtrT target);

  /// @brief Add data to tracking
  /// @tparam T The type of data
  /// @param addr The address of the struct
  /// @param data The new targets of the pointers
  template <class T> void addS(const PtrT addr, const T data) {
    for (auto offset : T::PTRS) {
      add(addr + (PtrT)offset, *(PtrT *)((uint8_t *)&data + offset));
    }
  }

  /// @brief Add pointer auth data for a pointer.
  /// @param addr Address of the pointer
  /// @param data The auth data
  void addAuth(const PtrT addr, AuthData data);

  /// @brief Copy and add auth data for a struct
  /// @tparam T The type of struct
  /// @param addr The address of the struct
  /// @param sAddr The address to copy auth data from
  template <class T> void copyAuthS(PtrT addr, PtrT sAddr) {
    // Check if the source address is within an auth mapping
    for (const auto map : authMappings) {
      if (map->containsAddr(sAddr)) {
        // Copy auth data for each pointer if needed
        auto sLoc = map->convertAddr(sAddr);
        for (auto offset : T::PTRS) {
          auto p = (dyld_cache_slide_pointer3 *)(sLoc + offset);
          if (p->auth.authenticated) {
            addAuth(addr + (PtrT)offset,
                    {(uint16_t)p->auth.diversityData,
                     (bool)p->auth.hasAddressDiversity, (uint8_t)p->auth.key});
          }
        }
        break;
      }
    }
  }

  /// @brief Add bind data for a pointer
  /// @param addr The address of the pointer
  /// @param data Symbolic info for the bind
  void addBind(const PtrT addr, const SymbolicInfo *data);

  /// @brief Get all mappings
  const std::vector<MappingSlideInfo> &getMappings() const;

  /// @brief Get all mappings with slide info
  const std::vector<const MappingSlideInfo *> &getSlideMappings() const;

  const std::map<PtrT, PtrT> &getPointers() const;

private:
  void fillMappings();

  const Dyld::Context *dCtx;
  std::shared_ptr<spdlog::logger> logger;

  std::vector<MappingSlideInfo> mappings;
  std::vector<const MappingSlideInfo *> slideMappings;
  std::vector<const MappingSlideInfo *> authMappings;

  std::map<PtrT, PtrT> pointers;
  std::unordered_map<PtrT, AuthData> authData;
  std::unordered_map<PtrT, const SymbolicInfo *> bindData;
};

}; // namespace Provider

#endif // __PROVIDER_POINTERTRACKER__
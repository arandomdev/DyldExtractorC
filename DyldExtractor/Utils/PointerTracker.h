#ifndef __UTILS_POINTERTRACKER__
#define __UTILS_POINTERTRACKER__

#include <map>
#include <stdint.h>

#include <Dyld/Context.h>

namespace Utils {

struct MappingSlideInfo {
    const uint8_t *dataStart;
    const uint64_t address;
    const uint64_t size;

    const uint32_t slideInfoVersion;
    const uint8_t *slideInfo;

    bool containsAddr(uint64_t addr) const;
    bool containsData(uint8_t *addr) const;
};

std::vector<MappingSlideInfo> getMappingSlideInfo(Dyld::Context &dCtx);

template <class P> struct TrackedPointer {
    uint8_t *loc;     // Pointer to pointer in the mCtx
    P::uint_t target; // The target VM address
    bool isBind;

    struct {
        uint16_t diversity;
        bool hasAddrDiv;
        uint8_t key;
    } auth;

    void setTarget(P::uint_t target);
    bool operator<(const TrackedPointer &other);
};

template <class P> class PointerTracker {
  private:
    typedef P::uint_t uint_t;

  public:
    PointerTracker(Dyld::Context &dCtx);

    /// Slide the pointer at the address.
    ///
    /// @param address The address of the pointer.
    /// @returns The slid pointer value.
    uint_t slideP(uint64_t address) const;

    /// Slide the struct at the address.
    ///
    /// @tparam T The type of struct.
    /// @param address The address of the struct.
    /// @returns The slid struct.
    template <class T> T slideS(uint64_t address) const {
        T data = *(T *)_dCtx.convertAddrP(address);
        for (auto const offset : T::PTRS::P) {
            *(uint_t *)((uint8_t *)&data + offset) = slideP(address + offset);
        }
        return data;
    }

    /// Add a pointer to tracking
    ///
    /// @param loc A pointer to the pointer in the mCtx.
    /// @param target The target vm address.
    /// @param authSource The address of the pointer for auth info.
    TrackedPointer<P> &trackP(uint8_t *loc, uint_t target, uint8_t *authSource);

  private:
    Dyld::Context &_dCtx;
    std::vector<MappingSlideInfo> _mappings;
    std::map<uint8_t *, TrackedPointer<P>> _pointers;
};

} // namespace Utils

#endif // __UTILS_POINTERTRACKER__
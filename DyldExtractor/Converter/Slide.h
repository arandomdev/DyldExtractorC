#ifndef __CONVERTER_SLIDE__
#define __CONVERTER_SLIDE__

#include <Utils/ExtractionContext.h>
#include <map>

namespace Converter {

struct MappingSlideInfo {
    const uint8_t *dataStart;
    const uint64_t address;
    const uint64_t size;

    const uint32_t slideInfoVersion;
    const uint8_t *slideInfo;

    bool containsAddr(const uint64_t addr) const;
    bool containsData(const uint8_t *addr) const;
};

template <class P>
std::vector<MappingSlideInfo>
getMappingSlideInfo(const Utils::ExtractionContext<P> &eCtx);

template <class P> struct TrackedPointer {
    uint8_t *loc;    // Pointer to pointer in the mCtx
    P::ptr_t target; // The target VM address
    bool isBind;

    struct {
        uint16_t diversity;
        bool hasAddrDiv;
        uint8_t key;
    } auth;

    void setTarget(const typename P::ptr_t target);
    bool operator<(const TrackedPointer &other);
};

template <class P> class PointerTracker {
  private:
    typedef P::ptr_t ptr_t;

  public:
    PointerTracker(const Utils::ExtractionContext<P> &eCtx);

    /// Slide the pointer at the address.
    ///
    /// @param address The address of the pointer.
    /// @returns The slid pointer value.
    ptr_t slideP(const uint64_t address) const;

    /// Slide the struct at the address.
    ///
    /// @tparam T The type of struct.
    /// @param address The address of the struct.
    /// @returns The slid struct.
    template <class T> T slideS(const uint64_t address) const {
        T data = *(T *)_dCtx.convertAddrP(address);
        for (auto const offset : T::PTRS::P) {
            *(ptr_t *)((uint8_t *)&data + offset) = slideP(address + offset);
        }
        return data;
    }

    /// Add a pointer to tracking
    ///
    /// @param loc A pointer to the pointer in the mCtx.
    /// @param target The target vm address.
    /// @param authSource The address of the pointer for auth info.
    TrackedPointer<P> &trackP(uint8_t *loc, const ptr_t target,
                              const uint8_t *authSource);

  private:
    const std::shared_ptr<spdlog::logger> _logger;
    const Dyld::Context &_dCtx;
    std::vector<MappingSlideInfo> _mappings;
    std::map<uint8_t *, TrackedPointer<P>> _pointers;
};

template <class P> void processSlideInfo(Utils::ExtractionContext<P> &eCtx);

} // namespace Converter

#endif // __CONVERTER_SLIDE__
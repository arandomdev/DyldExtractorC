#include "PointerTracker.h"

using namespace Utils;

bool MappingSlideInfo::containsAddr(uint64_t addr) const {
    return addr >= address && addr < address + size;
}

bool MappingSlideInfo::containsData(uint8_t *addr) const {
    return addr >= dataStart && addr < dataStart + size;
}

std::vector<MappingSlideInfo> Utils::getMappingSlideInfo(Dyld::Context &dCtx) {
    std::vector<MappingSlideInfo> mappingSlideInfo;

    if (dCtx.header->slideInfoOffsetUnused) {
        // Assume legacy case with no sub caches, and only one slide info
        auto slideInfo = dCtx.file + dCtx.header->slideInfoOffsetUnused;
        uint32_t slideVer = *(uint32_t *)slideInfo;

        // slide info corresponds to the second mapping
        auto mapping =
            (dyld_cache_mapping_info *)(dCtx.file + dCtx.header->mappingOffset +
                                        sizeof(dyld_cache_mapping_info));
        mappingSlideInfo.emplace_back(dCtx.file + mapping->fileOffset,
                                      mapping->address, mapping->size, slideVer,
                                      slideInfo);
        return mappingSlideInfo;
    }

    if (!dCtx.headerContainsMember(
            offsetof(dyld_cache_header, mappingWithSlideOffset))) {
        throw std::invalid_argument("Unable to get mapping and slide info");
    }

    // Get all mappings from all caches
    auto extendInfo = [&mappingSlideInfo](Dyld::Context &ctx) {
        if (!ctx.header->mappingWithSlideCount) {
            return;
        }
        auto start = (dyld_cache_mapping_and_slide_info
                          *)(ctx.file + ctx.header->mappingWithSlideOffset);
        auto end = start + ctx.header->mappingWithSlideCount;
        for (auto i = start; i < end; i++) {
            if (i->slideInfoFileOffset) {
                auto slideInfo = ctx.file + i->slideInfoFileOffset;
                auto slideVer = *(uint32_t *)slideInfo;
                mappingSlideInfo.emplace_back(ctx.file + i->fileOffset,
                                              i->address, i->size, slideVer,
                                              slideInfo);
            }
        }
    };

    extendInfo(dCtx);
    for (auto &ctx : dCtx.subcaches) {
        extendInfo(ctx);
    }

    return mappingSlideInfo;
}

template <class P> void TrackedPointer<P>::setTarget(P::uint_t target) {
    *(typename P::uint_t *)loc = target;
}

template <class P>
bool TrackedPointer<P>::operator<(const TrackedPointer &rhs) {
    return loc < rhs.loc;
}

template struct TrackedPointer<Utils::Pointer32>;
template struct TrackedPointer<Utils::Pointer64>;

template <class P>
PointerTracker<P>::PointerTracker(Dyld::Context &dCtx)
    : _dCtx(dCtx), _mappings(getMappingSlideInfo(dCtx)) {}

template <class P> P::uint_t PointerTracker<P>::slideP(uint64_t address) const {
    auto ptr = _dCtx.convertAddrP(address);
    for (auto &map : _mappings) {
        if (!map.containsAddr(address)) {
            return 0;
        }

        switch (map.slideInfoVersion) {
        case 1: {
            return *(uint_t *)ptr;
            break;
        }
        case 2: {
            return *(uint_t *)ptr & 0xffffffffff;
            break;
        }
        case 3: {
            auto ptrInfo = (dyld_cache_slide_pointer3 *)ptr;
            if (ptrInfo->auth.authenticated) {
                auto slideInfo = (dyld_cache_slide_info3 *)map.slideInfo;
                return (uint_t)ptrInfo->auth.offsetFromSharedCacheBase +
                       (uint_t)slideInfo->auth_value_add;
            } else {
                uint64_t value51 = ptrInfo->plain.pointerValue;
                uint64_t top8Bits = value51 & 0x0007F80000000000ULL;
                uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFFULL;
                return (uint_t)(top8Bits << 13) | (uint_t)bottom43Bits;
            }
            break;
        }
        case 4: {
            auto slideInfo = (dyld_cache_slide_info4 *)map.slideInfo;
            auto newValue = *(uint32_t *)ptr & ~(slideInfo->delta_mask);
            return (uint_t)newValue + (uint_t)slideInfo->value_add;
            break;
        }
        default:
            throw std::logic_error(std::format("Unknown slide info version {}",
                                               map.slideInfoVersion));
        }
    }

    return 0;
}

template <class P>
TrackedPointer<P> &PointerTracker<P>::trackP(uint8_t *loc, P::uint_t target,
                                             uint8_t *authSource) {
    if (_pointers.contains(loc)) {
        return _pointers[loc];
    }

    TrackedPointer<P> pointer = {0, 0, false, {0, false, 0}};
    pointer.loc = loc;
    pointer.target = target;

    if (authSource) {
        for (auto &map : _mappings) {
            if (map.containsData(authSource) && map.slideInfoVersion == 3) {
                auto ptrInfo = (dyld_cache_slide_pointer3 *)authSource;
                if (ptrInfo->auth.authenticated) {
                    pointer.auth.diversity = ptrInfo->auth.diversityData;
                    pointer.auth.hasAddrDiv = ptrInfo->auth.hasAddressDiversity;
                    pointer.auth.key = ptrInfo->auth.key;
                }
            }
        }
    }

    _pointers[loc] = pointer;
    return _pointers[loc];
}

template class PointerTracker<Utils::Pointer32>;
template class PointerTracker<Utils::Pointer64>;
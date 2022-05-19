#include "Slide.h"

#include <Utils/Architectures.h>
#include <spdlog/spdlog.h>

#ifdef _MSC_VER
#include <intrin.h>
static inline int __builtin_ctzll(unsigned long long x) {
    unsigned long ret;
    _BitScanForward64(&ret, x);
    return (int)ret;
}
#endif

using namespace Converter;

bool MappingSlideInfo::containsAddr(const uint64_t addr) const {
    return addr >= address && addr < address + size;
}

bool MappingSlideInfo::containsData(const uint8_t *addr) const {
    return addr >= dataStart && addr < dataStart + size;
}

template <class P>
std::vector<MappingSlideInfo>
Converter::getMappingSlideInfo(const Utils::ExtractionContext<P> &eCtx) {
    auto &dCtx = eCtx.dCtx;
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
        SPDLOG_LOGGER_ERROR(eCtx.logger,
                            "Unable to get mapping and slide info");
        return mappingSlideInfo;
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

template <class P>
void TrackedPointer<P>::setTarget(const typename P::ptr_t target) {
    *(typename P::ptr_t *)loc = target;
}

template <class P>
bool TrackedPointer<P>::operator<(const TrackedPointer &rhs) {
    return loc < rhs.loc;
}

template struct TrackedPointer<Utils::Pointer32>;
template struct TrackedPointer<Utils::Pointer64>;

template <class P>
PointerTracker<P>::PointerTracker(const Utils::ExtractionContext<P> &eCtx)
    : _dCtx(eCtx.dCtx), _mappings(getMappingSlideInfo(eCtx)) {}

template <class P>
P::ptr_t PointerTracker<P>::slideP(const uint64_t address) const {
    auto ptr = _dCtx.convertAddrP(address);
    for (auto &map : _mappings) {
        if (!map.containsAddr(address)) {
            continue;
        }

        switch (map.slideInfoVersion) {
        case 1: {
            return *(ptr_t *)ptr;
            break;
        }
        case 2: {
            return *(ptr_t *)ptr & 0xffffffffff;
            break;
        }
        case 3: {
            auto ptrInfo = (dyld_cache_slide_pointer3 *)ptr;
            if (ptrInfo->auth.authenticated) {
                auto slideInfo = (dyld_cache_slide_info3 *)map.slideInfo;
                return (ptr_t)ptrInfo->auth.offsetFromSharedCacheBase +
                       (ptr_t)slideInfo->auth_value_add;
            } else {
                uint64_t value51 = ptrInfo->plain.pointerValue;
                uint64_t top8Bits = value51 & 0x0007F80000000000ULL;
                uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFFULL;
                return (ptr_t)(top8Bits << 13) | (ptr_t)bottom43Bits;
            }
            break;
        }
        case 4: {
            auto slideInfo = (dyld_cache_slide_info4 *)map.slideInfo;
            auto newValue = *(uint32_t *)ptr & ~(slideInfo->delta_mask);
            return (ptr_t)newValue + (ptr_t)slideInfo->value_add;
            break;
        }
        default:
            SPDLOG_LOGGER_ERROR(_logger, "Unknown slide info version {}",
                                map.slideInfoVersion);
        }
    }

    return 0;
}

template <class P>
TrackedPointer<P> &PointerTracker<P>::trackP(uint8_t *loc,
                                             const typename P::ptr_t target,
                                             const uint8_t *authSource) {
    if (_pointers.contains(loc)) {
        return _pointers[loc];
    }

    uint16_t diversity = 0;
    bool hasAddrDiv = false;
    uint8_t key = 0;

    if (authSource) {
        for (auto &map : _mappings) {
            if (map.containsData(authSource) && map.slideInfoVersion == 3) {
                auto ptrInfo = (dyld_cache_slide_pointer3 *)authSource;
                if (ptrInfo->auth.authenticated) {
                    diversity = ptrInfo->auth.diversityData;
                    hasAddrDiv = ptrInfo->auth.hasAddressDiversity;
                    key = ptrInfo->auth.key;
                }
            }
        }
    }

    // return a reference to the pointer in the map
    // TrackedPointer<P> ptr = {loc, target, false, {diversity, hasAddrDiv,
    // key}};
    _pointers[loc] = {loc, target, false, {diversity, hasAddrDiv, key}};
    return _pointers[loc];
}

template class PointerTracker<Utils::Pointer32>;
template class PointerTracker<Utils::Pointer64>;

class V1Processor {
  public:
    V1Processor(Utils::ExtractionContext<Utils::Pointer32> &eCtx,
                MappingSlideInfo &mapSlideInfo);
    void run();

  private:
    Utils::ExtractionContext<Utils::Pointer32> &_eCtx;
    Macho::Context<false, Utils::Pointer32> &_mCtx;
    MappingSlideInfo &_mapInfo;
    dyld_cache_slide_info *_slideInfo;
};

V1Processor::V1Processor(Utils::ExtractionContext<Utils::Pointer32> &eCtx,
                         MappingSlideInfo &mapSlideInfo)
    : _eCtx(eCtx), _mCtx(eCtx.mCtx), _mapInfo(mapSlideInfo),
      _slideInfo((dyld_cache_slide_info *)mapSlideInfo.slideInfo) {
    assert(_mapInfo.slideInfoVersion == 1);
}

void V1Processor::run() {
    auto data = _mCtx.convertAddrP(_mapInfo.address);
    auto entries = (uint8_t *)_slideInfo + _slideInfo->entries_offset;
    auto toc = (uint16_t *)((uint8_t *)_slideInfo + _slideInfo->toc_offset);

    for (auto &seg : _mCtx.segments) {
        if (!_mapInfo.containsAddr(seg.command->vmaddr)) {
            continue;
        }

        auto tocStart = (seg.command->vmaddr - _mapInfo.address) / 4096;
        auto tocEnd = Utils::align(seg.command->vmaddr + seg.command->vmsize -
                                       _mapInfo.address,
                                   4096) /
                      4096;

        for (auto tocI = (uint32_t)tocStart; tocI < tocEnd; tocI++) {
            auto entry = &entries[toc[tocI] * _slideInfo->entries_size];
            auto page = data + (4096 * tocI);

            for (int entryI = 0; entryI < 128; entryI++) {
                auto byte = entry[entryI];
                if (byte != 0) {
                    for (int bitI = 0; bitI < 8; bitI++) {
                        if (byte & (1 << bitI)) {
                            auto loc = page + entryI * 8 * 4 + bitI * 4;
                            _eCtx.pointerTracker->trackP(loc, *loc, nullptr);
                        }
                    }
                }
            }

            _eCtx.activity->update();
        }
    }
}

template <class P> class V2Processor {
  public:
    V2Processor(Utils::ExtractionContext<P> &eCtx,
                MappingSlideInfo &mapSlideInfo);
    void run();

  private:
    void processPage(uint8_t *page, uint64_t pageOffset);

    using uintptr_t = P::ptr_t;

    Utils::ExtractionContext<P> &_eCtx;
    Macho::Context<false, P> &_mCtx;
    MappingSlideInfo &_mapInfo;
    dyld_cache_slide_info2 *_slideInfo;

    uintptr_t _deltaMask;
    unsigned _deltaShift;
    uintptr_t _valueMask;
    uintptr_t _valueAdd;
};

template <class P>
V2Processor<P>::V2Processor(Utils::ExtractionContext<P> &eCtx,
                            MappingSlideInfo &mapSlideInfo)
    : _eCtx(eCtx), _mCtx(eCtx.mCtx), _mapInfo(mapSlideInfo),
      _slideInfo((dyld_cache_slide_info2 *)mapSlideInfo.slideInfo) {
    assert(mapSlideInfo.slideInfoVersion == 2);

    _deltaMask = (uintptr_t)_slideInfo->delta_mask;
    _deltaShift = __builtin_ctzll(_deltaMask) - 2;
    _valueMask = ~_deltaMask;
    _valueAdd = (uintptr_t)_slideInfo->value_add;
}

template <class P> void V2Processor<P>::run() {
    const auto pageStarts =
        (uint16_t *)((uint8_t *)_slideInfo + _slideInfo->page_starts_offset);
    const auto pageExtras =
        (uint16_t *)((uint8_t *)_slideInfo + _slideInfo->page_extras_offset);
    auto dataStart = _mCtx.convertAddrP(_mapInfo.address);

    for (const auto &seg : _mCtx.segments) {
        if (!_mapInfo.containsAddr(seg.command->vmaddr)) {
            continue;
        }

        // Get relevant pages
        const auto startI =
            (seg.command->vmaddr - _mapInfo.address) / _slideInfo->page_size;
        const auto endI =
            Utils::align(seg.command->vmaddr + seg.command->vmsize -
                             _mapInfo.address,
                         _slideInfo->page_size) /
            _slideInfo->page_size;

        for (auto i = startI; i < endI; i++) {
            const auto page = pageStarts[i];
            auto pageData = dataStart + (i * _slideInfo->page_size);

            if (page == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
                continue;
            } else if (page & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) {
                uint16_t chainI = page & 0x3FFF;
                bool done = false;
                while (!done) {
                    uint16_t pInfo = pageExtras[chainI];
                    uint16_t pageStartOffset = (pInfo & 0x3FFF) * 4;
                    processPage(pageData, pageStartOffset);

                    done = pInfo & DYLD_CACHE_SLIDE_PAGE_ATTR_END;
                    chainI++;
                }
            } else if ((page & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) == 0) {
                // The page starts are 32bit jumps
                processPage(pageData, page * 4);
            } else {
                SPDLOG_LOGGER_ERROR(_eCtx.logger, "Unknown page start");
            }

            _eCtx.activity->update();
        }
    }
}

template <class P>
void V2Processor<P>::processPage(uint8_t *page, uint64_t pageOffset) {
    uint64_t delta = 1;
    while (delta != 0) {
        uint8_t *loc = page + pageOffset;
        uintptr_t rawValue = *((uintptr_t *)loc);
        delta = ((rawValue & _deltaMask) >> _deltaShift);
        uintptr_t newValue = (rawValue & _valueMask);
        if (newValue != 0) {
            newValue += _valueAdd;
        }

        // Add to tracking
        _eCtx.pointerTracker->trackP(loc, newValue, nullptr);
        *((uintptr_t *)loc) = newValue;
        pageOffset += delta;
    }
}

class V3Processor {
  public:
    V3Processor(Utils::ExtractionContext<Utils::Pointer64> &eCtx,
                MappingSlideInfo &mapSlideInfo);
    void run();

  private:
    void processPage(uint8_t *page, uint64_t delta);

    Utils::ExtractionContext<Utils::Pointer64> &_eCtx;
    Macho::Context<false, Utils::Pointer64> &_mCtx;
    MappingSlideInfo &_mapInfo;
    dyld_cache_slide_info3 *_slideInfo;
};

V3Processor::V3Processor(Utils::ExtractionContext<Utils::Pointer64> &eCtx,
                         MappingSlideInfo &mapSlideInfo)
    : _eCtx(eCtx), _mCtx(eCtx.mCtx), _mapInfo(mapSlideInfo),
      _slideInfo((dyld_cache_slide_info3 *)mapSlideInfo.slideInfo) {
    assert(mapSlideInfo.slideInfoVersion == 3);
}

void V3Processor::run() {
    auto pageStarts =
        (uint16_t *)((uint8_t *)_slideInfo +
                     offsetof(dyld_cache_slide_info3, page_starts));
    auto dataStart = _mCtx.convertAddrP(_mapInfo.address);

    for (auto &seg : _mCtx.segments) {
        if (!_mapInfo.containsAddr(seg.command->vmaddr)) {
            continue;
        }

        // Get relevant pages
        auto startI =
            (seg.command->vmaddr - _mapInfo.address) / _slideInfo->page_size;
        auto endI = Utils::align(seg.command->vmaddr + seg.command->vmsize -
                                     _mapInfo.address,
                                 _slideInfo->page_size) /
                    _slideInfo->page_size;

        for (auto i = startI; i < endI; i++) {
            auto page = pageStarts[i];
            if (page == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
                continue;
            } else {
                auto pageData = dataStart + (i * _slideInfo->page_size);
                processPage(pageData, page);
            }

            _eCtx.activity->update();
        }
    }
}

void V3Processor::processPage(uint8_t *page, uint64_t delta) {
    auto loc = (dyld_cache_slide_pointer3 *)page;
    do {
        loc += delta;
        delta = loc->plain.offsetToNextPointer;
        uint64_t newValue;
        if (loc->auth.authenticated) {
            newValue = loc->auth.offsetFromSharedCacheBase +
                       _slideInfo->auth_value_add;
        } else {
            uint64_t value51 = loc->plain.pointerValue;
            uint64_t top8Bits = value51 & 0x0007F80000000000ULL;
            uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFFULL;
            newValue = (top8Bits << 13) | bottom43Bits;
        }

        _eCtx.pointerTracker->trackP((uint8_t *)loc, newValue, (uint8_t *)loc);
        loc->raw = newValue;
    } while (delta != 0);
}

class V4Processor {
  public:
    V4Processor(Utils::ExtractionContext<Utils::Pointer32> &eCtx,
                MappingSlideInfo &mapSlideInfo);
    void run();

  private:
    void processPage(uint8_t *page, uint32_t pageOffset);

    Utils::ExtractionContext<Utils::Pointer32> &_eCtx;
    Macho::Context<false, Utils::Pointer32> &_mCtx;
    MappingSlideInfo &_mapInfo;
    dyld_cache_slide_info4 *_slideInfo;

    uint64_t _deltaMask;
    uint64_t _deltaShift;
    uint64_t _valueMask;
    uint64_t _valueAdd;
};

V4Processor::V4Processor(Utils::ExtractionContext<Utils::Pointer32> &eCtx,
                         MappingSlideInfo &mapSlideInfo)
    : _eCtx(eCtx), _mCtx(eCtx.mCtx), _mapInfo(mapSlideInfo),
      _slideInfo((dyld_cache_slide_info4 *)mapSlideInfo.slideInfo) {
    assert(mapSlideInfo.slideInfoVersion == 4);

    _deltaMask = _slideInfo->delta_mask;
    _deltaShift = __builtin_ctzll(_deltaMask) - 2;
    _valueMask = ~_deltaMask;
    _valueAdd = _slideInfo->value_add;
}

void V4Processor::run() {
    auto pageStarts =
        (uint16_t *)((uint8_t *)_slideInfo + _slideInfo->page_starts_offset);
    auto pageExtras =
        (uint16_t *)((uint8_t *)_slideInfo + _slideInfo->page_extras_offset);
    auto dataStart = _mCtx.convertAddrP(_mapInfo.address);

    for (auto &seg : _mCtx.segments) {
        if (!_mapInfo.containsAddr(seg.command->vmaddr)) {
            continue;
        }

        // Get relevant pages
        auto startI =
            (seg.command->vmaddr - _mapInfo.address) / _slideInfo->page_size;
        auto endI = Utils::align(seg.command->vmaddr + seg.command->vmsize -
                                     _mapInfo.address,
                                 _slideInfo->page_size) /
                    _slideInfo->page_size;

        for (auto i = startI; i < endI; i++) {
            auto page = pageStarts[i];
            auto pageData = dataStart + (i * _slideInfo->page_size);
            if (page == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE) {
                continue;
            } else if ((page & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) == 0) {
                processPage(pageData, page * 4);
            } else if (page & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) {
                auto extra = pageExtras + (page & DYLD_CACHE_SLIDE4_PAGE_INDEX);
                while (true) {
                    auto pageOff = (*extra & DYLD_CACHE_SLIDE4_PAGE_INDEX) * 4;
                    processPage(pageData, pageOff);
                    if (*extra & DYLD_CACHE_SLIDE4_PAGE_EXTRA_END) {
                        break;
                    } else {
                        extra++;
                    }
                }

            } else {
                SPDLOG_LOGGER_ERROR(_eCtx.logger, "Unknown page start");
            }

            _eCtx.activity->update();
        }
    }
}

void V4Processor::processPage(uint8_t *page, uint32_t pageOffset) {
    uint32_t delta = 1;
    while (delta != 0) {
        uint8_t *loc = page + pageOffset;
        uint32_t rawValue = *((uint32_t *)loc);
        delta = ((rawValue & _deltaMask) >> _deltaShift);
        uint32_t newValue = (rawValue & _valueMask);
        if ((newValue & 0xFFFF8000) == 0) {
            // small positive non-pointer, use as-is
        } else if ((newValue & 0x3FFF8000) == 0x3FFF8000) {
            // small negative non-pointer
            newValue |= 0xC0000000;
        } else {
            // pointer that needs rebasing
            newValue += (uint32_t)_valueAdd;
            _eCtx.pointerTracker->trackP(loc, newValue, nullptr);
        }
        *((uint32_t *)loc) = newValue;
        pageOffset += delta;
    }
}

template <class P>
void Converter::processSlideInfo(Utils::ExtractionContext<P> &eCtx) {
    eCtx.activity->update("Slide Info", "Processing slide info");
    eCtx.pointerTracker = new PointerTracker<P>(eCtx);

    auto mappings = getMappingSlideInfo(eCtx);
    if (!mappings.size()) {
        SPDLOG_LOGGER_WARN(eCtx.logger, "No slide mappings found.");
    }

    for (auto &map : mappings) {
        switch (map.slideInfoVersion) {
        case 1: {
            if constexpr (std::is_same<P, Utils::Pointer64>::value) {
                SPDLOG_LOGGER_ERROR(eCtx.logger,
                                    "Unable to handle 64bit V1 slide info.");
            } else {
                V1Processor(eCtx, map).run();
            }
            break;
        }
        case 2: {
            V2Processor<P>(eCtx, map).run();
            break;
        }
        case 3: {
            if constexpr (std::is_same<P, Utils::Pointer32>::value) {
                SPDLOG_LOGGER_ERROR(eCtx.logger,
                                    "Unable to handle 32bit V3 slide info.");
            } else {
                V3Processor(eCtx, map).run();
            }
            break;
        }
        case 4: {
            if constexpr (std::is_same<P, Utils::Pointer64>::value) {
                SPDLOG_LOGGER_ERROR(eCtx.logger,
                                    "Unable to handle 64bit V4 slide info.");
            } else {
                V4Processor(eCtx, map).run();
            }
            break;
        }
        default:
            throw std::logic_error(std::format("Unknown slide info version {}",
                                               map.slideInfoVersion));
        }
    }
}

template void Converter::processSlideInfo<Utils::Pointer32>(
    Utils::ExtractionContext<Utils::Pointer32> &eCtx);
template void Converter::processSlideInfo<Utils::Pointer64>(
    Utils::ExtractionContext<Utils::Pointer64> &eCtx);
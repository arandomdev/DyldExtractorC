#include "Slide.h"

#include <Utils/Architectures.h>
#include <Utils/PointerTracker.h>

#ifdef _MSC_VER
#include <intrin.h>
static inline int __builtin_ctzll(unsigned long long x) {
    unsigned long ret;
    _BitScanForward64(&ret, x);
    return (int)ret;
}
#endif

using namespace Converter;

class V1Processor {
  public:
    V1Processor(Utils::ExtractionContext<Utils::Pointer32> eCtx,
                Utils::MappingSlideInfo &mapSlideInfo);
    void run();

  private:
    Utils::ExtractionContext<Utils::Pointer32> _eCtx;
    Macho::Context<false, Utils::Pointer32> &_mCtx;
    Utils::MappingSlideInfo &_mapInfo;
    dyld_cache_slide_info *_slideInfo;
};

V1Processor::V1Processor(Utils::ExtractionContext<Utils::Pointer32> eCtx,
                         Utils::MappingSlideInfo &mapSlideInfo)
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
                            _eCtx.pointerTracker.trackP(loc, *loc, nullptr);
                        }
                    }
                }
            }

            _eCtx.activity.update();
        }
    }
}

class V2Processor {
  public:
    V2Processor(Utils::ExtractionContext<Utils::Pointer64> eCtx,
                Utils::MappingSlideInfo &mapSlideInfo);
    void run();

  private:
    void processPage(uint8_t *page, uint64_t pageOffset);

    Utils::ExtractionContext<Utils::Pointer64> _eCtx;
    Macho::Context<false, Utils::Pointer64> &_mCtx;
    Utils::MappingSlideInfo &_mapInfo;
    dyld_cache_slide_info2 *_slideInfo;

    uint64_t _deltaMask;
    uint64_t _deltaShift;
    uint64_t _valueMask;
    uint64_t _valueAdd;
};

V2Processor::V2Processor(Utils::ExtractionContext<Utils::Pointer64> eCtx,
                         Utils::MappingSlideInfo &mapSlideInfo)
    : _eCtx(eCtx), _mCtx(eCtx.mCtx), _mapInfo(mapSlideInfo),
      _slideInfo((dyld_cache_slide_info2 *)mapSlideInfo.slideInfo) {
    assert(mapSlideInfo.slideInfoVersion == 2);

    _deltaMask = _slideInfo->delta_mask;
    _deltaShift = __builtin_ctzll(_deltaMask) - 2;
    _valueMask = ~_deltaMask;
    _valueAdd = _slideInfo->value_add;
}

void V2Processor::run() {
    auto pageStarts =
        (uint16_t *)((uint8_t *)_slideInfo + _slideInfo->page_starts_offset);
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
            if (page == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
                continue;
            } else if (page & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) {
                _eCtx.logger->error("Unable to handle extra pages");
                continue;
            } else if ((page & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) == 0) {
                auto pageData = dataStart + (i * _slideInfo->page_size);
                // The page starts are 32bit jumps
                processPage(pageData, page * 4);
            } else {
                _eCtx.logger->error("Unknown page start");
            }

            _eCtx.activity.update();
        }
    }
}

void V2Processor::processPage(uint8_t *page, uint64_t pageOffset) {
    uint64_t delta = 1;
    while (delta != 0) {
        uint8_t *loc = page + pageOffset;
        uint64_t rawValue = *((uint64_t *)loc);
        delta = ((rawValue & _deltaMask) >> _deltaShift);
        uint64_t newValue = (rawValue & _valueMask);
        if (newValue != 0) {
            newValue += _valueAdd;
        }

        // Add to tracking
        _eCtx.pointerTracker.trackP(loc, newValue, nullptr);
        *((uint64_t *)loc) = newValue;
        pageOffset += delta;
    }
}

class V3Processor {
  public:
    V3Processor(Utils::ExtractionContext<Utils::Pointer64> eCtx,
                Utils::MappingSlideInfo &mapSlideInfo);
    void run();

  private:
    void processPage(uint8_t *page, uint64_t delta);

    Utils::ExtractionContext<Utils::Pointer64> _eCtx;
    Macho::Context<false, Utils::Pointer64> &_mCtx;
    Utils::MappingSlideInfo &_mapInfo;
    dyld_cache_slide_info3 *_slideInfo;
};

V3Processor::V3Processor(Utils::ExtractionContext<Utils::Pointer64> eCtx,
                         Utils::MappingSlideInfo &mapSlideInfo)
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

            _eCtx.activity.update();
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

        _eCtx.pointerTracker.trackP((uint8_t *)loc, newValue, (uint8_t *)loc);
        loc->raw = newValue;
    } while (delta != 0);
}

class V4Processor {
  public:
    V4Processor(Utils::ExtractionContext<Utils::Pointer32> eCtx,
                Utils::MappingSlideInfo &mapSlideInfo);
    void run();

  private:
    void processPage(uint8_t *page, uint32_t pageOffset);

    Utils::ExtractionContext<Utils::Pointer32> _eCtx;
    Macho::Context<false, Utils::Pointer32> &_mCtx;
    Utils::MappingSlideInfo &_mapInfo;
    dyld_cache_slide_info4 *_slideInfo;

    uint64_t _deltaMask;
    uint64_t _deltaShift;
    uint64_t _valueMask;
    uint64_t _valueAdd;
};

V4Processor::V4Processor(Utils::ExtractionContext<Utils::Pointer32> eCtx,
                         Utils::MappingSlideInfo &mapSlideInfo)
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
                do {
                    auto pageOff = (*extra & DYLD_CACHE_SLIDE4_PAGE_INDEX) * 4;
                    processPage(pageData, pageOff);
                } while (!(*extra & DYLD_CACHE_SLIDE4_PAGE_EXTRA_END));

            } else {
                _eCtx.logger->error("Unknown page start");
            }

            _eCtx.activity.update();
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
            _eCtx.pointerTracker.trackP(loc, newValue, nullptr);
        }
        *((uint32_t *)loc) = newValue;
        pageOffset += delta;
    }
}

template <class P>
void Converter::processSlideInfo(Utils::ExtractionContext<P> eCtx) {
    eCtx.activity.update("Slide Info", "Processing slide info");

    auto mappings = Utils::getMappingSlideInfo(eCtx.dCtx);
    if (!mappings.size()) {
        eCtx.logger->warn("No slide mappings found.");
    }

    for (auto &map : mappings) {
        switch (map.slideInfoVersion) {
        case 1: {
            if constexpr (std::is_same<P, Utils::Pointer64>::value) {
                eCtx.logger->error("Unable to handle 64bit V1 slide info.");
            } else {
                V1Processor(eCtx, map).run();
            }
            break;
        }
        case 2: {
            if constexpr (std::is_same<P, Utils::Pointer32>::value) {
                eCtx.logger->error("Unable to handle 32bit V2 slide info.");
            } else {
                V2Processor(eCtx, map).run();
            }
            break;
        }
        case 3: {
            if constexpr (std::is_same<P, Utils::Pointer32>::value) {
                eCtx.logger->error("Unable to handle 32bit V3 slide info.");
            } else {
                V3Processor(eCtx, map).run();
            }
            break;
        }
        case 4: {
            if constexpr (std::is_same<P, Utils::Pointer64>::value) {
                eCtx.logger->error("Unable to handle 64bit V4 slide info.");
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
    Utils::ExtractionContext<Utils::Pointer32> eCtx);
template void Converter::processSlideInfo<Utils::Pointer64>(
    Utils::ExtractionContext<Utils::Pointer64> eCtx);
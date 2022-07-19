#include "Slide.h"

#include <Provider/PointerTracker.h>
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

#pragma region V1Processor
class V1Processor {
public:
  V1Processor(Utils::ExtractionContext<Utils::Pointer32> &eCtx,
              const Provider::PointerTracker<Utils::Pointer32>::MappingSlideInfo
                  &mapSlideInfo);
  void run();

private:
  Utils::ExtractionContext<Utils::Pointer32> &eCtx;
  Macho::Context<false, Utils::Pointer32> &mCtx;
  const Provider::PointerTracker<Utils::Pointer32>::MappingSlideInfo &mapInfo;
  dyld_cache_slide_info *slideInfo;
};

V1Processor::V1Processor(
    Utils::ExtractionContext<Utils::Pointer32> &eCtx,
    const Provider::PointerTracker<Utils::Pointer32>::MappingSlideInfo
        &mapSlideInfo)
    : eCtx(eCtx), mCtx(eCtx.mCtx), mapInfo(mapSlideInfo),
      slideInfo((dyld_cache_slide_info *)mapSlideInfo.slideInfo) {
  assert(mapInfo.slideInfoVersion == 1);
}

void V1Processor::run() {
  auto data = mCtx.convertAddrP(mapInfo.address);
  auto entries = (uint8_t *)slideInfo + slideInfo->entries_offset;
  auto toc = (uint16_t *)((uint8_t *)slideInfo + slideInfo->toc_offset);

  for (auto &seg : mCtx.segments) {
    if (!mapInfo.containsAddr(seg.command->vmaddr)) {
      continue;
    }

    auto tocStart = (seg.command->vmaddr - mapInfo.address) / 4096;
    auto tocEnd =
        Utils::align(
            seg.command->vmaddr + seg.command->vmsize - mapInfo.address, 4096) /
        4096;

    for (auto tocI = (uint32_t)tocStart; tocI < tocEnd; tocI++) {
      auto entry = &entries[toc[tocI] * slideInfo->entries_size];
      auto page = data + (4096 * tocI);

      for (int entryI = 0; entryI < 128; entryI++) {
        auto byte = entry[entryI];
        if (byte != 0) {
          for (int bitI = 0; bitI < 8; bitI++) {
            if (byte & (1 << bitI)) {
              auto loc = page + entryI * 8 * 4 + bitI * 4;
              eCtx.pointerTracker.trackP(loc, *loc, nullptr);
            }
          }
        }
      }

      eCtx.activity.get().update();
    }
  }
}
#pragma endregion V1Processor

#pragma region V2Processor
template <class P> class V2Processor {
public:
  V2Processor(Utils::ExtractionContext<P> &eCtx,
              const typename Provider::PointerTracker<P>::MappingSlideInfo
                  &mapSlideInfo);
  void run();

private:
  void processPage(uint8_t *page, uint64_t pageOffset);

  using uintptr_t = P::PtrT;

  Utils::ExtractionContext<P> &eCtx;
  Macho::Context<false, P> &mCtx;
  const typename Provider::PointerTracker<P>::MappingSlideInfo &mapInfo;
  dyld_cache_slide_info2 *slideInfo;

  uintptr_t deltaMask;
  unsigned deltaShift;
  uintptr_t valueMask;
  uintptr_t valueAdd;
};

template <class P>
V2Processor<P>::V2Processor(
    Utils::ExtractionContext<P> &eCtx,
    const typename Provider::PointerTracker<P>::MappingSlideInfo &mapSlideInfo)
    : eCtx(eCtx), mCtx(eCtx.mCtx), mapInfo(mapSlideInfo),
      slideInfo((dyld_cache_slide_info2 *)mapSlideInfo.slideInfo) {
  assert(mapSlideInfo.slideInfoVersion == 2);

  deltaMask = (uintptr_t)slideInfo->delta_mask;
  deltaShift = __builtin_ctzll(deltaMask) - 2;
  valueMask = ~deltaMask;
  valueAdd = (uintptr_t)slideInfo->value_add;
}

template <class P> void V2Processor<P>::run() {
  const auto pageStarts =
      (uint16_t *)((uint8_t *)slideInfo + slideInfo->page_starts_offset);
  const auto pageExtras =
      (uint16_t *)((uint8_t *)slideInfo + slideInfo->page_extras_offset);
  auto dataStart = mCtx.convertAddrP(mapInfo.address);

  for (const auto &seg : mCtx.segments) {
    if (!mapInfo.containsAddr(seg.command->vmaddr)) {
      continue;
    }

    // Get relevant pages
    const auto startI =
        (seg.command->vmaddr - mapInfo.address) / slideInfo->page_size;
    const auto endI = Utils::align(seg.command->vmaddr + seg.command->vmsize -
                                       mapInfo.address,
                                   slideInfo->page_size) /
                      slideInfo->page_size;

    for (auto i = startI; i < endI; i++) {
      const auto page = pageStarts[i];
      auto pageData = dataStart + (i * slideInfo->page_size);

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
        SPDLOG_LOGGER_ERROR(eCtx.logger, "Unknown page start");
      }

      eCtx.activity.get().update();
    }
  }
}

template <class P>
void V2Processor<P>::processPage(uint8_t *page, uint64_t pageOffset) {
  uint64_t delta = 1;
  while (delta != 0) {
    uint8_t *loc = page + pageOffset;
    uintptr_t rawValue = *((uintptr_t *)loc);
    delta = ((rawValue & deltaMask) >> deltaShift);
    uintptr_t newValue = (rawValue & valueMask);
    if (newValue != 0) {
      newValue += valueAdd;
    }

    // Add to tracking
    eCtx.pointerTracker.trackP(loc, newValue, nullptr);
    *((uintptr_t *)loc) = newValue;
    pageOffset += delta;
  }
}
#pragma endregion V2Processor

#pragma region V3Processor
class V3Processor {
public:
  V3Processor(Utils::ExtractionContext<Utils::Pointer64> &eCtx,
              const Provider::PointerTracker<Utils::Pointer64>::MappingSlideInfo
                  &mapSlideInfo);
  void run();

private:
  void processPage(uint8_t *page, uint64_t delta);

  Utils::ExtractionContext<Utils::Pointer64> &eCtx;
  Macho::Context<false, Utils::Pointer64> &mCtx;
  const Provider::PointerTracker<Utils::Pointer64>::MappingSlideInfo &mapInfo;
  dyld_cache_slide_info3 *slideInfo;
};

V3Processor::V3Processor(
    Utils::ExtractionContext<Utils::Pointer64> &eCtx,
    const Provider::PointerTracker<Utils::Pointer64>::MappingSlideInfo
        &mapSlideInfo)
    : eCtx(eCtx), mCtx(eCtx.mCtx), mapInfo(mapSlideInfo),
      slideInfo((dyld_cache_slide_info3 *)mapSlideInfo.slideInfo) {
  assert(mapSlideInfo.slideInfoVersion == 3);
}

void V3Processor::run() {
  auto pageStarts = (uint16_t *)((uint8_t *)slideInfo +
                                 offsetof(dyld_cache_slide_info3, page_starts));
  auto dataStart = mCtx.convertAddrP(mapInfo.address);

  for (auto &seg : mCtx.segments) {
    if (!mapInfo.containsAddr(seg.command->vmaddr)) {
      continue;
    }

    // Get relevant pages
    auto startI =
        (seg.command->vmaddr - mapInfo.address) / slideInfo->page_size;
    auto endI = Utils::align(seg.command->vmaddr + seg.command->vmsize -
                                 mapInfo.address,
                             slideInfo->page_size) /
                slideInfo->page_size;

    for (auto i = startI; i < endI; i++) {
      auto page = pageStarts[i];
      if (page == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
        continue;
      } else {
        auto pageData = dataStart + (i * slideInfo->page_size);
        processPage(pageData, page);
      }

      eCtx.activity.get().update();
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
      newValue =
          loc->auth.offsetFromSharedCacheBase + slideInfo->auth_value_add;
    } else {
      uint64_t value51 = loc->plain.pointerValue;
      uint64_t top8Bits = value51 & 0x0007F80000000000ULL;
      uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFFULL;
      newValue = (top8Bits << 13) | bottom43Bits;
    }

    eCtx.pointerTracker.trackP((uint8_t *)loc, newValue, (uint8_t *)loc);
    loc->raw = newValue;
  } while (delta != 0);
}
#pragma endregion V3Processor

#pragma region V4Processor
class V4Processor {
public:
  V4Processor(Utils::ExtractionContext<Utils::Pointer32> &eCtx,
              const Provider::PointerTracker<Utils::Pointer32>::MappingSlideInfo
                  &mapSlideInfo);
  void run();

private:
  void processPage(uint8_t *page, uint32_t pageOffset);

  Utils::ExtractionContext<Utils::Pointer32> &eCtx;
  Macho::Context<false, Utils::Pointer32> &mCtx;
  const Provider::PointerTracker<Utils::Pointer32>::MappingSlideInfo &mapInfo;
  dyld_cache_slide_info4 *slideInfo;

  uint64_t deltaMask;
  uint64_t deltaShift;
  uint64_t valueMask;
  uint64_t valueAdd;
};

V4Processor::V4Processor(
    Utils::ExtractionContext<Utils::Pointer32> &eCtx,
    const Provider::PointerTracker<Utils::Pointer32>::MappingSlideInfo
        &mapSlideInfo)
    : eCtx(eCtx), mCtx(eCtx.mCtx), mapInfo(mapSlideInfo),
      slideInfo((dyld_cache_slide_info4 *)mapSlideInfo.slideInfo) {
  assert(mapSlideInfo.slideInfoVersion == 4);

  deltaMask = slideInfo->delta_mask;
  deltaShift = __builtin_ctzll(deltaMask) - 2;
  valueMask = ~deltaMask;
  valueAdd = slideInfo->value_add;
}

void V4Processor::run() {
  auto pageStarts =
      (uint16_t *)((uint8_t *)slideInfo + slideInfo->page_starts_offset);
  auto pageExtras =
      (uint16_t *)((uint8_t *)slideInfo + slideInfo->page_extras_offset);
  auto dataStart = mCtx.convertAddrP(mapInfo.address);

  for (auto &seg : mCtx.segments) {
    if (!mapInfo.containsAddr(seg.command->vmaddr)) {
      continue;
    }

    // Get relevant pages
    auto startI =
        (seg.command->vmaddr - mapInfo.address) / slideInfo->page_size;
    auto endI = Utils::align(seg.command->vmaddr + seg.command->vmsize -
                                 mapInfo.address,
                             slideInfo->page_size) /
                slideInfo->page_size;

    for (auto i = startI; i < endI; i++) {
      auto page = pageStarts[i];
      auto pageData = dataStart + (i * slideInfo->page_size);
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
        SPDLOG_LOGGER_ERROR(eCtx.logger, "Unknown page start");
      }

      eCtx.activity.get().update();
    }
  }
}

void V4Processor::processPage(uint8_t *page, uint32_t pageOffset) {
  uint32_t delta = 1;
  while (delta != 0) {
    uint8_t *loc = page + pageOffset;
    uint32_t rawValue = *((uint32_t *)loc);
    delta = ((rawValue & deltaMask) >> deltaShift);
    uint32_t newValue = (rawValue & valueMask);
    if ((newValue & 0xFFFF8000) == 0) {
      // small positive non-pointer, use as-is
    } else if ((newValue & 0x3FFF8000) == 0x3FFF8000) {
      // small negative non-pointer
      newValue |= 0xC0000000;
    } else {
      // pointer that needs rebasing
      newValue += (uint32_t)valueAdd;
      eCtx.pointerTracker.trackP(loc, newValue, nullptr);
    }
    *((uint32_t *)loc) = newValue;
    pageOffset += delta;
  }
}
#pragma endregion V4Processor

template <class P>
void Converter::processSlideInfo(Utils::ExtractionContext<P> &eCtx) {
  eCtx.activity.get().update("Slide Info", "Processing slide info");

  const auto &mappings = eCtx.pointerTracker.getMappings();
  if (!mappings.size()) {
    SPDLOG_LOGGER_WARN(eCtx.logger, "No slide mappings found.");
  }

  for (const auto &map : mappings) {
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
      throw std::logic_error(
          fmt::format("Unknown slide info version {}", map.slideInfoVersion));
    }
  }
}

template void Converter::processSlideInfo<Utils::Pointer32>(
    Utils::ExtractionContext<Utils::Pointer32> &eCtx);
template void Converter::processSlideInfo<Utils::Pointer64>(
    Utils::ExtractionContext<Utils::Pointer64> &eCtx);
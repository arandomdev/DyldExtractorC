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

using namespace DyldExtractor;
using namespace Converter;

#pragma region V1Processor
class V1Processor {
  using P = Utils::Arch::Pointer32;
  using PtrT = P::PtrT;

public:
  V1Processor(
      Macho::Context<false, P> &mCtx, Logger::Activity &activity,
      Provider::PointerTracker<P> &ptrTracker,
      const Provider::PointerTracker<P>::MappingSlideInfo &mapSlideInfo);
  void run();

private:
  Macho::Context<false, P> &mCtx;
  Logger::Activity &activity;
  Provider::PointerTracker<P> &ptrTracker;

  const Provider::PointerTracker<P>::MappingSlideInfo &mapInfo;
  dyld_cache_slide_info *slideInfo;
};

V1Processor::V1Processor(
    Macho::Context<false, P> &mCtx, Logger::Activity &activity,
    Provider::PointerTracker<P> &ptrTracker,
    const Provider::PointerTracker<P>::MappingSlideInfo &mapSlideInfo)
    : mCtx(mCtx), activity(activity), ptrTracker(ptrTracker),
      mapInfo(mapSlideInfo),
      slideInfo((dyld_cache_slide_info *)mapSlideInfo.slideInfo) {
  assert(mapInfo.slideInfoVersion == 1);
}

void V1Processor::run() {
  auto addr = mapInfo.address;
  auto data = mCtx.convertAddrP(addr);
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
      auto pageAddr = addr + (4096 * tocI);
      auto pageData = data + (4096 * tocI);

      for (int entryI = 0; entryI < 128; entryI++) {
        auto byte = entry[entryI];
        if (byte != 0) {
          for (int bitI = 0; bitI < 8; bitI++) {
            if (byte & (1 << bitI)) {
              auto pAddr = pageAddr + entryI * 8 * 4 + bitI * 4;
              auto pLoc = pageData + entryI * 8 * 4 + bitI * 4;
              ptrTracker.add((PtrT)pAddr, *(PtrT *)pLoc);
            }
          }
        }
      }

      activity.update();
    }
  }
}
#pragma endregion V1Processor

#pragma region V2Processor
template <class P> class V2Processor {
  using PtrT = P::PtrT;

public:
  V2Processor(Macho::Context<false, P> &mCtx, Logger::Activity &activity,
              std::shared_ptr<spdlog::logger> logger,
              Provider::PointerTracker<P> &ptrTracker,
              const typename Provider::PointerTracker<P>::MappingSlideInfo
                  &mapSlideInfo);
  void run();

private:
  void processPage(uint64_t pageAddr, uint8_t *pageData, uint64_t pageOffset);

  Macho::Context<false, P> &mCtx;
  Logger::Activity &activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::PointerTracker<P> &ptrTracker;

  const typename Provider::PointerTracker<P>::MappingSlideInfo &mapInfo;
  dyld_cache_slide_info2 *slideInfo;

  PtrT deltaMask;
  unsigned deltaShift;
  PtrT valueMask;
  PtrT valueAdd;
};

template <class P>
V2Processor<P>::V2Processor(
    Macho::Context<false, P> &mCtx, Logger::Activity &activity,
    std::shared_ptr<spdlog::logger> logger,
    Provider::PointerTracker<P> &ptrTracker,
    const typename Provider::PointerTracker<P>::MappingSlideInfo &mapSlideInfo)
    : mCtx(mCtx), activity(activity), logger(logger), ptrTracker(ptrTracker),
      mapInfo(mapSlideInfo),
      slideInfo((dyld_cache_slide_info2 *)mapSlideInfo.slideInfo) {
  assert(mapSlideInfo.slideInfoVersion == 2);

  deltaMask = (PtrT)slideInfo->delta_mask;
  deltaShift = __builtin_ctzll(deltaMask) - 2;
  valueMask = ~deltaMask;
  valueAdd = (PtrT)slideInfo->value_add;
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
      auto pageAddr = mapInfo.address + (i * slideInfo->page_size);
      auto pageData = dataStart + (i * slideInfo->page_size);

      if (page == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
        continue;
      } else if (page & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) {
        uint16_t chainI = page & 0x3FFF;
        bool done = false;
        while (!done) {
          uint16_t pInfo = pageExtras[chainI];
          uint16_t pageStartOffset = (pInfo & 0x3FFF) * 4;
          processPage(pageAddr, pageData, pageStartOffset);

          done = pInfo & DYLD_CACHE_SLIDE_PAGE_ATTR_END;
          chainI++;
        }
      } else if ((page & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) == 0) {
        // The page starts are 32bit jumps
        processPage(pageAddr, pageData, page * 4);
      } else {
        SPDLOG_LOGGER_ERROR(logger, "Unknown page start");
      }

      activity.update();
    }
  }
}

template <class P>
void V2Processor<P>::processPage(uint64_t pageAddr, uint8_t *pageData,
                                 uint64_t pageOffset) {
  uint64_t delta = 1;
  while (delta != 0) {
    auto pAddr = (PtrT)(pageAddr + pageOffset);
    uint8_t *pLoc = pageData + pageOffset;
    PtrT rawValue = *((PtrT *)pLoc);
    delta = ((rawValue & deltaMask) >> deltaShift);
    PtrT newValue = (rawValue & valueMask);
    if (newValue != 0) {
      newValue += valueAdd;
    }

    // Add to tracking
    ptrTracker.add(pAddr, newValue);
    pageOffset += delta;
  }
}
#pragma endregion V2Processor

#pragma region V3Processor
class V3Processor {
  using P = Utils::Arch::Pointer64;
  using PtrT = P::PtrT;

public:
  V3Processor(
      Macho::Context<false, P> &mCtx, Logger::Activity &activity,
      Provider::PointerTracker<P> &ptrTracker,
      const Provider::PointerTracker<P>::MappingSlideInfo &mapSlideInfo);
  void run();

private:
  void processPage(uint64_t pageAddr, uint8_t *pageData, uint64_t delta);

  Macho::Context<false, P> &mCtx;
  Logger::Activity &activity;
  Provider::PointerTracker<P> &ptrTracker;

  const Provider::PointerTracker<P>::MappingSlideInfo &mapInfo;
  dyld_cache_slide_info3 *slideInfo;
};

V3Processor::V3Processor(
    Macho::Context<false, P> &mCtx, Logger::Activity &activity,
    Provider::PointerTracker<P> &ptrTracker,
    const Provider::PointerTracker<P>::MappingSlideInfo &mapSlideInfo)
    : mCtx(mCtx), activity(activity), ptrTracker(ptrTracker),
      mapInfo(mapSlideInfo),
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
        auto pageAddr = mapInfo.address + (i * slideInfo->page_size);
        auto pageData = dataStart + (i * slideInfo->page_size);
        // Page is a byte offset into page data, delta is 8 byte stride
        processPage(pageAddr, pageData, page / sizeof(PtrT));
      }

      activity.update();
    }
  }
}

void V3Processor::processPage(uint64_t pageAddr, uint8_t *pageData,
                              uint64_t delta) {
  auto pAddr = pageAddr;
  auto pLoc = (dyld_cache_slide_pointer3 *)pageData;
  do {
    pAddr += delta * sizeof(PtrT);
    pLoc += delta;

    delta = pLoc->plain.offsetToNextPointer;
    uint64_t newValue;
    if (pLoc->auth.authenticated) {
      newValue =
          pLoc->auth.offsetFromSharedCacheBase + slideInfo->auth_value_add;
      ptrTracker.addAuth(pAddr, {(uint16_t)pLoc->auth.diversityData,
                                 (bool)pLoc->auth.hasAddressDiversity,
                                 (uint8_t)pLoc->auth.key});
    } else {
      uint64_t value51 = pLoc->plain.pointerValue;
      uint64_t top8Bits = value51 & 0x0007F80000000000ULL;
      uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFFULL;
      newValue = (top8Bits << 13) | bottom43Bits;
    }

    ptrTracker.add(pAddr, newValue);
    pLoc->raw = newValue;
  } while (delta != 0);
}
#pragma endregion V3Processor

#pragma region V4Processor
class V4Processor {
  using P = Utils::Arch::Pointer32;

public:
  V4Processor(
      Macho::Context<false, P> &mCtx, Logger::Activity &activity,
      std::shared_ptr<spdlog::logger> logger,
      Provider::PointerTracker<P> &ptrTracker,
      const Provider::PointerTracker<P>::MappingSlideInfo &mapSlideInfo);
  void run();

private:
  void processPage(uint32_t pageAddr, uint8_t *pageData, uint32_t pageOffset);

  Macho::Context<false, P> &mCtx;
  Logger::Activity &activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::PointerTracker<P> &ptrTracker;

  const Provider::PointerTracker<P>::MappingSlideInfo &mapInfo;
  dyld_cache_slide_info4 *slideInfo;

  uint64_t deltaMask;
  uint64_t deltaShift;
  uint64_t valueMask;
  uint64_t valueAdd;
};

V4Processor::V4Processor(
    Macho::Context<false, P> &mCtx, Logger::Activity &activity,
    std::shared_ptr<spdlog::logger> logger,
    Provider::PointerTracker<P> &ptrTracker,
    const Provider::PointerTracker<P>::MappingSlideInfo &mapSlideInfo)
    : mCtx(mCtx), activity(activity), logger(logger), ptrTracker(ptrTracker),
      mapInfo(mapSlideInfo),
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
      auto pageAddr = (uint32_t)(mapInfo.address + (i * slideInfo->page_size));
      auto pageData = dataStart + (i * slideInfo->page_size);

      if (page == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE) {
        continue;
      } else if ((page & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) == 0) {
        processPage(pageAddr, pageData, page * 4);
      } else if (page & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) {
        auto extra = pageExtras + (page & DYLD_CACHE_SLIDE4_PAGE_INDEX);
        while (true) {
          auto pageOff = (*extra & DYLD_CACHE_SLIDE4_PAGE_INDEX) * 4;
          processPage(pageAddr, pageData, pageOff);
          if (*extra & DYLD_CACHE_SLIDE4_PAGE_EXTRA_END) {
            break;
          } else {
            extra++;
          }
        }

      } else {
        SPDLOG_LOGGER_ERROR(logger, "Unknown page start");
      }

      activity.update();
    }
  }
}

void V4Processor::processPage(uint32_t pageAddr, uint8_t *pageData,
                              uint32_t pageOffset) {
  uint32_t delta = 1;
  while (delta != 0) {
    uint32_t pAddr = pageAddr + pageOffset;
    uint8_t *pLoc = pageData + pageOffset;

    uint32_t rawValue = *((uint32_t *)pLoc);
    delta = ((rawValue & deltaMask) >> deltaShift);
    uint32_t newValue = (rawValue & valueMask);
    if ((newValue & 0xFFFF8000) == 0) {
      // small positive non-pointer, use as-is
      *((uint32_t *)pLoc) = newValue;
    } else if ((newValue & 0x3FFF8000) == 0x3FFF8000) {
      // small negative non-pointer
      newValue |= 0xC0000000;
      *((uint32_t *)pLoc) = newValue;
    } else {
      // pointer that needs rebasing
      newValue += (uint32_t)valueAdd;
      ptrTracker.add(pAddr, newValue);
    }
    pageOffset += delta;
  }
}
#pragma endregion V4Processor

template <class A>
void Converter::processSlideInfo(Utils::ExtractionContext<A> &eCtx) {
  using P = A::P;

  auto &mCtx = *eCtx.mCtx;
  auto &activity = *eCtx.activity;
  auto logger = eCtx.logger;
  auto &ptrTracker = eCtx.ptrTracker;

  activity.update("Slide Info", "Processing slide info");

  const auto &mappings = eCtx.ptrTracker.getSlideMappings();
  if (!mappings.size()) {
    SPDLOG_LOGGER_WARN(logger, "No slide mappings found.");
  }

  for (const auto &map : mappings) {
    switch (map->slideInfoVersion) {
    case 1: {
      if constexpr (std::is_same<P, Utils::Arch::Pointer64>::value) {
        SPDLOG_LOGGER_ERROR(logger, "Unable to handle 64bit V1 slide info.");
      } else {
        V1Processor(mCtx, activity, ptrTracker, *map).run();
      }
      break;
    }
    case 2: {
      V2Processor<P>(mCtx, activity, logger, ptrTracker, *map).run();
      break;
    }
    case 3: {
      if constexpr (std::is_same<P, Utils::Arch::Pointer32>::value) {
        SPDLOG_LOGGER_ERROR(logger, "Unable to handle 32bit V3 slide info.");
      } else {
        V3Processor(mCtx, activity, ptrTracker, *map).run();
      }
      break;
    }
    case 4: {
      if constexpr (std::is_same<P, Utils::Arch::Pointer64>::value) {
        SPDLOG_LOGGER_ERROR(logger, "Unable to handle 64bit V4 slide info.");
      } else {
        V4Processor(mCtx, activity, logger, ptrTracker, *map).run();
      }
      break;
    }
    default:
      throw std::logic_error(
          fmt::format("Unknown slide info version {}", map->slideInfoVersion));
    }
  }
}

#define X(T)                                                                   \
  template void Converter::processSlideInfo<T>(Utils::ExtractionContext<T> &   \
                                               eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X
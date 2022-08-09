#include "PointerTracker.h"

#include <Utils/ExtractionContext.h>

using namespace Provider;

template <class P>
bool PointerTracker<P>::MappingSlideInfo::containsAddr(
    const uint64_t addr) const {
  return addr >= address && addr < address + size;
}

template <class P>
const uint8_t *
PointerTracker<P>::MappingSlideInfo::convertAddr(const uint64_t addr) const {
  return (addr - address) + data;
}

template <class P>
PointerTracker<P>::PointerTracker(const Dyld::Context &dCtx,
                                  std::shared_ptr<spdlog::logger> logger)
    : dCtx(&dCtx), logger(logger) {
  fillMappings();
}

template <class P>
PointerTracker<P>::PtrT PointerTracker<P>::slideP(const PtrT addr) const {
  for (auto &map : mappings) {
    if (!map.containsAddr(addr)) {
      continue;
    }
    auto ptr = map.convertAddr(addr);

    switch (map.slideInfoVersion) {
    case 1: {
      return *(PtrT *)ptr;
      break;
    }
    case 2: {
      auto slideInfo = (dyld_cache_slide_info2 *)map.slideInfo;
      auto val = *(PtrT *)ptr & ~slideInfo->delta_mask;
      if (val != 0) {
        val += slideInfo->value_add;
      }
      return (PtrT)val;
      break;
    }
    case 3: {
      auto ptrInfo = (dyld_cache_slide_pointer3 *)ptr;
      if (ptrInfo->auth.authenticated) {
        auto slideInfo = (dyld_cache_slide_info3 *)map.slideInfo;
        return (PtrT)ptrInfo->auth.offsetFromSharedCacheBase +
               (PtrT)slideInfo->auth_value_add;
      } else {
        uint64_t value51 = ptrInfo->plain.pointerValue;
        uint64_t top8Bits = value51 & 0x0007F80000000000ULL;
        uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFFULL;
        return (PtrT)(top8Bits << 13) | (PtrT)bottom43Bits;
      }
      break;
    }
    case 4: {
      auto slideInfo = (dyld_cache_slide_info4 *)map.slideInfo;
      auto newValue = *(uint32_t *)ptr & ~(slideInfo->delta_mask);
      return (PtrT)newValue + (PtrT)slideInfo->value_add;
      break;
    }
    default:
      SPDLOG_LOGGER_ERROR(logger, "Unknown slide info version {}",
                          map.slideInfoVersion);
    }
  }

  return 0;
}

template <class P>
void PointerTracker<P>::add(const PtrT addr, const PtrT target) {
  pointers[addr] = target;
}

template <class P>
void PointerTracker<P>::addAuth(const PtrT addr, AuthData data) {
  authData[addr] = data;
}

template <class P>
void PointerTracker<P>::addBind(const PtrT addr, const SymbolicInfo *data) {
  bindData[addr] = data;
}

template <class P>
const std::vector<typename PointerTracker<P>::MappingSlideInfo> &
PointerTracker<P>::getMappings() const {
  return mappings;
}

template <class P>
const std::vector<const typename PointerTracker<P>::MappingSlideInfo *> &
PointerTracker<P>::getSlideMappings() const {
  return slideMappings;
}

template <class P>
const std::map<typename PointerTracker<P>::PtrT,
               typename PointerTracker<P>::PtrT> &
PointerTracker<P>::getPointers() const {
  return pointers;
}

template <class P> void PointerTracker<P>::fillMappings() {
  if (dCtx->header->slideInfoOffsetUnused) {
    // Assume legacy case with no sub caches, and only one slide info
    auto slideInfo = dCtx->file + dCtx->header->slideInfoOffsetUnused;
    uint32_t slideVer = *(uint32_t *)slideInfo;

    // slide info corresponds to the second mapping
    auto mapping =
        (dyld_cache_mapping_info *)(dCtx->file + dCtx->header->mappingOffset +
                                    sizeof(dyld_cache_mapping_info));
    mappings.emplace_back(dCtx->file + mapping->fileOffset, mapping->address,
                          mapping->size, slideVer, slideInfo);
    return;
  }

  if (!dCtx->headerContainsMember(
          offsetof(dyld_cache_header, mappingWithSlideOffset))) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to get mapping and slide info");
    return;
  }

  // Get all mappings from all caches
  auto extendInfo = [this](const Dyld::Context &ctx) {
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
        mappings.emplace_back(ctx.file + i->fileOffset, i->address, i->size,
                              slideVer, slideInfo);
      } else {
        mappings.emplace_back(ctx.file + i->fileOffset, i->address, i->size, 0,
                              nullptr);
      }
    }
  };

  extendInfo(*dCtx);
  for (auto &ctx : dCtx->subcaches) {
    extendInfo(ctx);
  }

  // fill other mappings as mappings should be constant now
  for (const auto &map : mappings) {
    if (map.slideInfo != nullptr) {
      slideMappings.push_back(&map);
    }
    if (map.slideInfoVersion == 3) {
      authMappings.push_back(&map);
    }
  }
}

template class PointerTracker<Utils::Pointer32>;
template class PointerTracker<Utils::Pointer64>;
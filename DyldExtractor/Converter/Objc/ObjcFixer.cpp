#include "ObjcFixer.h"

#include <Objc/Abstraction.h>
#include <dyld/objc-shared-cache.h>

using namespace Converter;

#pragma region ObjcFixer
template <class A>
ObjcFixer<A>::ObjcFixer(Utils::ExtractionContext<A> &eCtx)
    : dCtx(*eCtx.dCtx), mCtx(*eCtx.mCtx), activity(*eCtx.activity),
      logger(eCtx.logger), ptrTracker(eCtx.pointerTracker),
      symbolizer(eCtx.symbolizer), exObjc(eCtx.exObjc) {}

template <class A> void ObjcFixer<A>::fix() {
  bool optimized = false;
  if (auto sect = mCtx.getSection(nullptr, "__objc_imageinfo").second; sect) {
    auto info = (Objc::image_info *)mCtx.convertAddrP(sect->addr);
    if (info->flags & 0x8) {
      // clear optimized by Dyld flag
      info->flags &= ~0x8;
      optimized = true;
    }
  }

  if (!optimized) {
    SPDLOG_LOGGER_DEBUG(logger, "Objc not optimized by Dyld");
    return;
  }

  if (!detectMethodNameStorage()) {
    return;
  }

  allocateDataRegion();
  processSections();
}

template <class A> bool ObjcFixer<A>::detectMethodNameStorage() {
  // Get libobjc
  const dyld_cache_image_info *libobjcImageInfo;
  for (const auto info : dCtx.images) {
    if (strstr((const char *)dCtx.file + info->pathFileOffset, "/libobjc.") !=
        nullptr) {
      libobjcImageInfo = info;
      break;
    }
  }
  if (!libobjcImageInfo) {
    SPDLOG_LOGGER_WARN(logger, "Unable to find image info for libobjc");
    return false;
  }
  auto libobjcImage = dCtx.createMachoCtx<true, P>(libobjcImageInfo);

  // Get __objc_opt_data
  auto optRoSect = libobjcImage.getSection(nullptr, "__objc_opt_ro").second;
  if (optRoSect) {
    auto optData =
        (objc_opt::objc_opt_t *)libobjcImage.convertAddrP(optRoSect->addr);

    // Starting with version 16, method names are relative to a base address
    // rather than to itself
    if (optData->version >= 16 &&
        optData->relativeMethodSelectorBaseAddressOffset) {
      relMethodNameBaseLoc = libobjcImage.convertAddrP(
          optRoSect->addr + optData->relativeMethodSelectorBaseAddressOffset);
    }

    if (optData->version != 16) {
      /// TODO: Remove
      SPDLOG_LOGGER_DEBUG(logger, "Found opt data with unknown version {}",
                          optData->version);
    }
  } else {
    /// TODO: Remove
    SPDLOG_LOGGER_DEBUG(logger, "unable to find __objc_opt_data");
  }

  return true;
}

template <class A> void ObjcFixer<A>::allocateDataRegion() {
  // Find segment with highest address, while below linkedit
  PtrT dataStart = 0;
  for (const auto &seg : mCtx.segments) {
    if (memcmp(seg.command->segname, SEG_LINKEDIT, 11) == 0) {
      continue;
    }

    auto segEnd = seg.command->vmaddr + seg.command->vmsize;
    if (segEnd > dataStart) {
      dataStart = segEnd;
    }
  }

  // Align
  Utils::align(&dataStart, (PtrT)sizeof(PtrT));
  exObjc = Provider::ExtraData<P>(dataStart);
}

template <class A> void ObjcFixer<A>::processSections() {
  mCtx.enumerateSections([this](const auto seg, const auto sect) {
    if (memcmp(sect->sectname, "__objc_classlist", 16) == 0) {
      activity.update(std::nullopt, "Processing Classes");
      auto pLoc = (PtrT *)mCtx.convertAddrP(sect->addr);
      for (PtrT pAddr = sect->addr; pAddr < sect->addr + sect->size;
           pAddr += sizeof(PtrT), pLoc += sizeof(PtrT)) {
        activity.update();
        auto cAddr = ptrTracker.slideP(pAddr);
        if (mCtx.containsAddr(cAddr)) {
          *pLoc = processClass(cAddr).first;
        } else {
          SPDLOG_LOGGER_WARN(
              logger, "Class pointer at {:#x} points outside of image.", pAddr);
        }
      }
    }

    return true;
  });
}

template <class A>
std::pair<bool, typename ObjcFixer<A>::PtrT>
ObjcFixer<A>::processClass(const PtrT cAddr, std::set<PtrT> processing_) {
  if (processing_.contains(cAddr)) {
    return std::make_pair(false, 0);
  }
  auto processingIt = processing_.insert(cAddr).first;

  if (cache.classes.contains(cAddr)) {
    return std::make_pair(true, cache.classes.at(cAddr));
  }

  // Process data
  auto cData = ptrTracker.slideS<Objc::class_t<P>>(cAddr);
  if (cData.isa) {
    if (mCtx.containsAddr(cData.isa)) {
      auto [defined, newIsaAddr] = processClass(cData.isa);
      if (defined) {
        cData.isa = newIsaAddr;
      } else {
        cache.futureClassFixes[cAddr + offsetof(Objc::class_t<P>, isa)] =
            cData.isa;
      }
    } else {
      if (auto info = symbolizer.symbolizeAddr(cData.isa); info) {
        ptrTracker.addBind(cAddr + offsetof(Objc::class_t<P>, isa), info);
      } else {
        SPDLOG_LOGGER_WARN(
            logger, "Unable to symbolize isa for class_t at {:#x}", cAddr);
      }
    }
  }

  if (cData.superclass) {
    if (mCtx.containsAddr(cData.superclass)) {
      auto [defined, newSuperclassAddr] = processClass(cData.superclass);
      if (defined) {
        cData.superclass = newSuperclassAddr;
      } else {
        cache.futureClassFixes[cAddr + offsetof(Objc::class_t<P>, superclass)] =
            cData.superclass;
      }
    } else {
      if (auto info = symbolizer.symbolizeAddr(cData.superclass); info) {
        ptrTracker.addBind(cAddr + offsetof(Objc::class_t<P>, superclass),
                           info);
      } else {
        SPDLOG_LOGGER_WARN(
            logger, "Unable to symbolize superclass for class_t at {:#x}",
            cAddr);
      }
    }
  }

  /// TODO: IMP
  if (cData.method_cache) {
  }
  if (cData.vtable) {
  }
  if (cData.data) {
  }

  // Commit data
  auto newCAddr = cAddr;
  if (mCtx.containsAddr(cAddr)) {
    *(Objc::class_t<P> *)mCtx.convertAddrP(cAddr) = cData;
  } else {
    newCAddr = exObjc.add(cData);
  }
  ptrTracker.addS(newCAddr, cData);
  ptrTracker.copyAuthS<Objc::class_t<P>>(newCAddr, cAddr);

  cache.classes[cAddr] = newCAddr;
  processing_.erase(processingIt);
  return std::make_pair(true, newCAddr);
}

template <class A> void ObjcFixer<A>::processFutureClasses() {
  for (auto [addr, target] : cache.futureClassFixes) {
    if (cache.classes.contains(addr)) {
      ptrTracker.add(addr, cache.classes.at(addr));
    }
  }
}
#pragma endregion ObjcFixer

template <class A> void Converter::fixObjc(Utils::ExtractionContext<A> &eCtx) {
  eCtx.activity->update("Fixing Objc");
  ObjcFixer(eCtx).fix();
}

#define X(T)                                                                   \
  template void Converter::fixObjc<T>(Utils::ExtractionContext<T> & eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X
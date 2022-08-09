#include "RebaseGenerator.h"

#include "../Objc.h"

using namespace Converter;

/// @brief Updates all tracked pointers to their targets
template <class A> void applyFixups(Utils::ExtractionContext<A> &eCtx) {
  using PtrT = A::P::PtrT;

  auto &pointers = eCtx.pointerTracker.getPointers();
  for (auto seg : eCtx.mCtx->segments) {
    auto command = seg.command;
    uint8_t *segData;
    if (strcmp(command->segname, SEG_OBJC_EXTRA) == 0) {
      segData = eCtx.exObjc.get<uint8_t>(command->vmaddr);
    } else {
      segData = eCtx.mCtx->convertAddrP(command->vmaddr);
    }

    // process all pointers within the segment
    auto beginIt = pointers.lower_bound(command->vmaddr);
    auto endIt = pointers.upper_bound(command->vmaddr + command->vmsize);
    for (auto it = beginIt; it != endIt; it++) {
      auto [addr, target] = *it;
      *(PtrT *)(segData + (addr - command->vmaddr)) = target;
    }
  }
}

template <class A>
void Converter::generateRebase(Utils::ExtractionContext<A> &eCtx) {
  if (auto dyldInfo =
          eCtx.mCtx->getLoadCommand<false, Macho::Loader::dyld_info_command>();
      dyldInfo) {
    // Use old encoding
    applyFixups(eCtx);
  } else {
    SPDLOG_LOGGER_ERROR(eCtx.logger, "imp no encoding");
  }
}

#define X(T)                                                                   \
  template void Converter::generateRebase<T>(Utils::ExtractionContext<T> &     \
                                             eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X
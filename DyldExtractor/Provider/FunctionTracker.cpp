#include "FunctionTracker.h"

#include <Utils/Leb128.h>

using namespace DyldExtractor;
using namespace Provider;

template <class P>
FunctionTracker<P>::FunctionTracker(const Macho::Context<false, P> &mCtx,
                                    std::shared_ptr<spdlog::logger> logger)
    : mCtx(&mCtx), logger(logger) {}

template <class P> void FunctionTracker<P>::load() {
  if (loaded) {
    return;
  }
  loaded = true;

  auto [textSeg, textSect] = mCtx->getSection(SEG_TEXT, SECT_TEXT);
  auto leSeg = mCtx->getSegment(SEG_LINKEDIT)->command;

  auto funcStartsCmd = mCtx->getFirstLC<Macho::Loader::linkedit_data_command>(
      {LC_FUNCTION_STARTS});
  const uint8_t *leFile = mCtx->convertAddr(leSeg->vmaddr).second;
  const uint8_t *p = leFile + funcStartsCmd->dataoff;
  const uint8_t *const end = p + funcStartsCmd->datasize;

  PtrT funcAddr = textSeg->command->vmaddr + (PtrT)Utils::readUleb128(p, end);
  if (funcAddr == textSeg->command->vmaddr) {
    return;
  }

  while (*p) {
    PtrT next = (PtrT)Utils::readUleb128(p, end);
    functions.emplace_back(funcAddr, next);
    funcAddr += next;
  }

  // Add last function
  functions.emplace_back(funcAddr, textSect->addr + textSect->size - funcAddr);
}

template <class P>
const std::vector<typename FunctionTracker<P>::Function> &
FunctionTracker<P>::getFunctions() const {
  return functions;
}

template class FunctionTracker<Utils::Arch::Pointer32>;
template class FunctionTracker<Utils::Arch::Pointer64>;
#include "Validator.h"
#include <Utils/Architectures.h>

using namespace DyldExtractor;
using namespace Provider;

template <class P>
Validator<P>::Validator(const Macho::Context<false, P> &mCtx) : mCtx(&mCtx) {}

template <class P> void Validator<P>::validate() {
  if (!mCtx->getSegment(SEG_LINKEDIT)) {
    throw std::exception("Missing Linkedit segment.");
  }

  if (!mCtx->getSegment(SEG_TEXT)) {
    throw std::exception("Missing Text segment.");
  }

  if (!mCtx->getSection(SEG_TEXT, SECT_TEXT).second) {
    throw std::exception("Missing text section.");
  }

  if (!mCtx->getFirstLC<Macho::Loader::symtab_command>()) {
    throw std::exception("Missing symtab command.");
  }

  if (!mCtx->getFirstLC<Macho::Loader::dysymtab_command>()) {
    throw std::exception("Missing dysymtab command.");
  }

  if (memcmp(mCtx->segments.back().command->segname, SEG_LINKEDIT,
             sizeof(SEG_LINKEDIT)) != 0) {
    throw std::exception(
        "Linkedit segment is not the last segment load command.");
  }

  {
    // Linkedit highest addr
    PtrT maxSegAddr = 0;
    PtrT leAddr = 0;
    for (const auto &seg : mCtx->segments) {
      if (memcmp(seg.command->segname, SEG_LINKEDIT, sizeof(SEG_LINKEDIT)) ==
          0) {
        leAddr = seg.command->vmaddr;
      } else {
        if (seg.command->vmaddr > maxSegAddr) {
          maxSegAddr = seg.command->vmaddr;
        }
      }
    }

    if (maxSegAddr > leAddr) {
      throw std::exception(
          "Linkedit segment does not have the highest address.");
    }

    if (leAddr % 0x4000) {
      throw std::exception(
          "Linkedit segment is not address aligned to 0x4000.");
    }
  }

  if (!mCtx->getFirstLC<Macho::Loader::linkedit_data_command>(
          {LC_FUNCTION_STARTS})) {
    throw std::exception("Missing function starts command.");
  }
}

template class Validator<Utils::Arch::Pointer32>;
template class Validator<Utils::Arch::Pointer64>;
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

  auto [seg, sect] = mCtx->getSection(SEG_TEXT, SECT_TEXT);
  if (!sect) {
    throw std::exception("Missing text section.");
  }

  if (!mCtx->getFirstLC<Macho::Loader::symtab_command>()) {
    throw std::exception("Missing symtab command.");
  }

  if (!mCtx->getFirstLC<Macho::Loader::dysymtab_command>()) {
    throw std::exception("Missing dysymtab command.");
  }
}

template class Validator<Utils::Arch::Pointer32>;
template class Validator<Utils::Arch::Pointer64>;
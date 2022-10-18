#include "OffsetOptimizer.h"
#include "Macho/Loader.h"

#include <exception>

using namespace DyldExtractor;
using namespace Converter;

// Update all linkedit data commands
template <class P>
void updateLinkedit(Macho::Context<false, P> &mCtx, int32_t shiftDelta) {
  for (auto linkeditData :
       mCtx.getAllLCs<Macho::Loader::linkedit_data_command>()) {
    linkeditData->dataoff += linkeditData->dataoff ? shiftDelta : 0;
  }

  auto dyldInfo = mCtx.getFirstLC<Macho::Loader::dyld_info_command>();
  if (dyldInfo != nullptr) {
    dyldInfo->rebase_off += dyldInfo->rebase_off ? shiftDelta : 0;
    dyldInfo->bind_off += dyldInfo->bind_off ? shiftDelta : 0;
    dyldInfo->weak_bind_off += dyldInfo->weak_bind_off ? shiftDelta : 0;
    dyldInfo->lazy_bind_off += dyldInfo->lazy_bind_off ? shiftDelta : 0;
    dyldInfo->export_off += dyldInfo->export_off ? shiftDelta : 0;
  }

  auto symtab = mCtx.getFirstLC<Macho::Loader::symtab_command>();
  symtab->symoff += symtab->symoff ? shiftDelta : 0;
  symtab->stroff += symtab->stroff ? shiftDelta : 0;

  auto dysymtab = mCtx.getFirstLC<Macho::Loader::dysymtab_command>();
  dysymtab->tocoff += dysymtab->tocoff ? shiftDelta : 0;
  dysymtab->ntoc += dysymtab->ntoc ? shiftDelta : 0;
  dysymtab->modtaboff += dysymtab->modtaboff ? shiftDelta : 0;
  dysymtab->extrefsymoff += dysymtab->extrefsymoff ? shiftDelta : 0;
  dysymtab->indirectsymoff += dysymtab->indirectsymoff ? shiftDelta : 0;
  dysymtab->extreloff += dysymtab->extreloff ? shiftDelta : 0;
  dysymtab->locreloff += dysymtab->locreloff ? shiftDelta : 0;
}

template <class A>
std::vector<OffsetWriteProcedure>
Converter::optimizeOffsets(Utils::ExtractionContext<A> &eCtx) {
  eCtx.activity->update("Offset Optimizer", "Updating Offsets");
  auto &mCtx = *eCtx.mCtx;

  std::vector<OffsetWriteProcedure> procedures;
  uint32_t dataHead = 0;
  for (auto &segment : mCtx.segments) {
    // verify sizes
    if (segment.command->fileoff > UINT32_MAX ||
        segment.command->filesize > UINT32_MAX) {
      throw std::invalid_argument(
          "Segment has too big of a fileoff or filesize, likely a "
          "malformed segment command.");
    }

    // create procedure
    auto segData = mCtx.convertAddrP(segment.command->vmaddr);
    procedures.emplace_back(dataHead, segData, segment.command->filesize);

    // shift the segment and sections
    int32_t shiftDelta = dataHead - (uint32_t)segment.command->fileoff;
    segment.command->fileoff += shiftDelta;
    for (auto &section : segment.sections) {
      section->offset += shiftDelta;
    }

    if (memcmp(&segment.command->segname, SEG_LINKEDIT, sizeof(SEG_LINKEDIT)) ==
        0) {
      updateLinkedit(mCtx, shiftDelta);
    }

    // update and page align dataHead
    dataHead += (uint32_t)segment.command->filesize;
    dataHead = ((dataHead + 0x3FFF) & (-0x4000));
  }

  return procedures;
}

#define X(T)                                                                   \
  template std::vector<OffsetWriteProcedure> Converter::optimizeOffsets<T>(    \
      Utils::ExtractionContext<T> & eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X
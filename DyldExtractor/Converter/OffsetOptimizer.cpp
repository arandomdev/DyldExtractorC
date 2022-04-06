#include "OffsetOptimizer.h"
#include "Macho/Loader.h"

#include <exception>

using namespace Converter;

// Update all linkedit data commands
template <class P>
void updateLinkedit(Macho::Context<false, P> *machoCtx, int32_t shiftDelta) {
    for (auto linkeditData :
         machoCtx
             ->getLoadCommand<true, Macho::Loader::linkedit_data_command>()) {
        linkeditData->dataoff += linkeditData->dataoff ? shiftDelta : 0;
    }

    auto dyldInfo =
        machoCtx->getLoadCommand<false, Macho::Loader::dyld_info_command>();
    if (dyldInfo != nullptr) {
        dyldInfo->rebase_off += dyldInfo->rebase_off ? shiftDelta : 0;
        dyldInfo->bind_off += dyldInfo->bind_off ? shiftDelta : 0;
        dyldInfo->weak_bind_off += dyldInfo->weak_bind_off ? shiftDelta : 0;
        dyldInfo->lazy_bind_off += dyldInfo->lazy_bind_off ? shiftDelta : 0;
        dyldInfo->export_off += dyldInfo->export_off ? shiftDelta : 0;
    }

    auto symtab =
        machoCtx->getLoadCommand<false, Macho::Loader::symtab_command>();
    if (symtab != nullptr) {
        symtab->symoff += symtab->symoff ? shiftDelta : 0;
        symtab->stroff += symtab->stroff ? shiftDelta : 0;
    }

    auto dysymtab =
        machoCtx->getLoadCommand<false, Macho::Loader::dysymtab_command>();
    if (dysymtab != nullptr) {
        dysymtab->tocoff += dysymtab->tocoff ? shiftDelta : 0;
        dysymtab->ntoc += dysymtab->ntoc ? shiftDelta : 0;
        dysymtab->modtaboff += dysymtab->modtaboff ? shiftDelta : 0;
        dysymtab->extrefsymoff += dysymtab->extrefsymoff ? shiftDelta : 0;
        dysymtab->indirectsymoff += dysymtab->indirectsymoff ? shiftDelta : 0;
        dysymtab->extreloff += dysymtab->extreloff ? shiftDelta : 0;
        dysymtab->locreloff += dysymtab->locreloff ? shiftDelta : 0;
    }
}

template <class P>
std::vector<WriteProcedure>
Converter::optimizeOffsets(Utils::ExtractionContext<P> extractionCtx) {
    auto machoCtx = extractionCtx.machoCtx;

    std::vector<WriteProcedure> procedures;
    uint32_t dataHead = 0;
    for (auto &segment : machoCtx->segments) {
        // verify sizes
        if (segment.command->fileoff > UINT32_MAX ||
            segment.command->filesize > UINT32_MAX) {
            throw std::invalid_argument(
                "Segment has too big of a fileoff or filesize, likely a "
                "malformed segment command.");
        }

        // create procedure
        auto [segOff, segCtx] = machoCtx->convertAddr(segment.command->vmaddr);
        procedures.emplace_back(dataHead, segCtx + segOff,
                                segment.command->filesize);

        // shift the segment and sections
        int32_t shiftDelta = dataHead - (uint32_t)segment.command->fileoff;
        segment.command->fileoff += shiftDelta;
        for (auto &section : segment.sections) {
            section->offset += shiftDelta;
        }

        if (memcmp(&segment.command->segname, "__LINKEDIT\x00", 11) == 0) {
            updateLinkedit(machoCtx, shiftDelta);
        }

        // update and page align dataHead
        dataHead += (uint32_t)segment.command->filesize;
        dataHead = ((dataHead + 0x3FFF) & (-0x4000));
    }

    return procedures;
}

template std::vector<WriteProcedure>
Converter::optimizeOffsets<Utils::Pointer32>(
    Utils::ExtractionContext<Utils::Pointer32> extractionCtx);
template std::vector<WriteProcedure>
Converter::optimizeOffsets<Utils::Pointer64>(
    Utils::ExtractionContext<Utils::Pointer64> extractionCtx);
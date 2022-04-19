#include "HeaderTracker.h"

using namespace Utils;

template <class P>
HeaderTracker<P>::HeaderTracker(Macho::Context<false, P> &mCtx)
    : _header(mCtx.header) {
    auto textSect = mCtx.getSection("__TEXT", "__text");
    if (!textSect) {
        throw std::invalid_argument(
            "Mach-O Context doesn't have a __text sect.");
    }
    auto textSectStart = mCtx.convertAddrP(textSect->addr);
    _commandsStart =
        (uint8_t *)_header + sizeof(Macho::Context<false, P>::HeaderT);
    _headerSpaceAvailable = (uint32_t)(textSectStart - _commandsStart);

    auto linkeditSeg = mCtx.getSegment("__LINKEDIT");
    if (!linkeditSeg) {
        throw std::invalid_argument(
            "Mach-O Context doesn't have a __LINKEDIT segment.");
    }
    _linkeditStart = mCtx.convertAddrP(linkeditSeg->command->vmaddr);
    _linkeditEnd = _linkeditStart + linkeditSeg->command->vmsize;
}

template <class P>
bool HeaderTracker<P>::insertLoadCommand(Macho::Loader::load_command *after,
                                         Macho::Loader::load_command *lc) {
    // Make sure there is enough space
    if (_header->sizeofcmds + lc->cmdsize > _headerSpaceAvailable) {
        return false;
    }

    // Move all load commands after `after`
    std::size_t shiftDelta = lc->cmdsize;
    uint8_t *shiftStart = (uint8_t *)after + after->cmdsize;
    uint8_t *shiftEnd = _commandsStart + _header->sizeofcmds;
    memmove(shiftStart + shiftDelta, shiftStart, shiftEnd - shiftStart);

    memcpy(shiftStart, lc, lc->cmdsize);

    // Adjust tracking pointers
    for (auto &ptrPair : trackingData) {
        if (ptrPair.offset >= shiftStart) {
            ptrPair.offset += shiftDelta;
        }
    }

    // Adjust header
    _header->ncmds++;
    _header->sizeofcmds += lc->cmdsize;
    return true;
}

template <class P>
bool HeaderTracker<P>::insertLinkeditData(std::optional<LinkeditData> after,
                                          LinkeditData data) {
    // calculate shift amount with pointer align
    uint32_t shiftDelta = data.dataSize + (8 - (data.dataSize % 8));

    // Check that there is enough space
    uint8_t *lastDataEnd;
    if (trackingData.size()) {
        auto lastData = *trackingData.rbegin();
        lastDataEnd = lastData.data + lastData.dataSize;
    } else {
        lastDataEnd = _linkeditStart;
    }
    if (lastDataEnd + shiftDelta > _linkeditEnd) {
        return false;
    }

    // Shift all data after `after`
    uint8_t *shiftStart =
        after ? after->data + after->dataSize : _linkeditStart;
    memmove(shiftStart + shiftDelta, shiftStart, lastDataEnd - shiftStart);

    // Update tracking data
    for (auto &trackedData : trackingData) {
        if (trackedData.data >= shiftStart) {
            *(uint32_t *)trackedData.offset += shiftDelta;
            trackedData.data += shiftDelta;
        }
    }

    // zero out pointer align padding and set data
    memset(shiftStart + shiftDelta - 8, 0, 8);
    memcpy(shiftStart, data.data, data.dataSize);

    // update data and add to tracking
    data.data = shiftStart;
    data.dataSize = shiftDelta; // include padding
    trackData(data);
    return true;
}

template <class P> void HeaderTracker<P>::trackData(LinkeditData data) {
    auto it =
        std::lower_bound(trackingData.begin(), trackingData.end(), data,
                         [](const LinkeditData &a, const LinkeditData &b) {
                             return a.data < b.data;
                         });
    trackingData.insert(it, data);
}

template class HeaderTracker<Utils::Pointer32>;
template class HeaderTracker<Utils::Pointer64>;
#include "OffsetOptimizer.h"

#include <Macho/Loader.h>
#include <Objc/Abstraction.h>
#include <Utils/Utils.h>
#include <exception>

using namespace DyldExtractor;
using namespace Converter;

/// @brief Checks and makes room for the extra objc segment
/// @return A pair of pointers, first is the extra data if available, the second
///   is the linkedit data.
template <class A> bool checkExtraObjc(Utils::ExtractionContext<A> &eCtx) {
  const auto &mCtx = *eCtx.mCtx;
  if (!eCtx.exObjc) {
    return false;
  }
  const auto &exObjc = eCtx.exObjc.value();

  // sort segments by address and find segments
  auto segs = mCtx.segments;
  std::sort(segs.begin(), segs.end(), [](const auto &a, const auto &b) {
    return a.command->vmaddr < b.command->vmaddr;
  });

  auto extendsSegIt =
      std::find_if(segs.begin(), segs.end(), [&exObjc](const auto &a) {
        return strncmp(a.command->segname, exObjc.getExtendsSeg().c_str(),
                       16) == 0;
      });
  auto linkeditIt = std::find_if(segs.begin(), segs.end(), [](const auto &a) {
    return strncmp(a.command->segname, SEG_LINKEDIT, 16) == 0;
  });

  assert(extendsSegIt != segs.end());            // Found extends seg
  assert(std::next(extendsSegIt) != segs.end()); // It's not the linkedit
  assert(linkeditIt != segs.end());              // Found linkedit

  // Make more room if necessary
  auto exObjcEndAddr = exObjc.getEndAddr();
  auto nextSegIt = std::next(extendsSegIt);
  if (exObjcEndAddr > nextSegIt->command->vmaddr) {
    if (nextSegIt == linkeditIt) {
      // Can move the linkedit to make room
      linkeditIt->command->vmaddr =
          Utils::align(exObjcEndAddr, SEGMENT_ALIGNMENT);
    } else {
      SPDLOG_LOGGER_ERROR(eCtx.logger,
                          "Unable to make room for the extra ObjC segment.");
      return false;
    }
  }

  return true;
}

template <class A>
std::vector<OffsetWriteProcedure>
Converter::optimizeOffsets(Utils::ExtractionContext<A> &eCtx) {
  eCtx.activity->update("Offset Optimizer", "Updating Offsets");
  auto &mCtx = *eCtx.mCtx;

  std::vector<OffsetWriteProcedure> procedures;

  if (!eCtx.leTracker) {
    SPDLOG_LOGGER_ERROR(
        eCtx.logger,
        "Offset optimizer and output depends on linkedit optimizer.");
    return procedures; // empty
  }

  // verify sizes
  for (const auto seg : mCtx.segments) {
    if (seg.command->fileoff > UINT32_MAX ||
        seg.command->filesize > UINT32_MAX) {
      SPDLOG_LOGGER_ERROR(eCtx.logger,
                          "Segment has too big of a fileoff or filesize, "
                          "likely a malformed segment command.");
      return procedures; // empty
    }
  }

  bool writeExObjc = checkExtraObjc(eCtx);
  uint32_t dataHead = 0;
  for (auto &seg : mCtx.segments) {
    bool isLinkedit = strncmp(seg.command->segname, SEG_LINKEDIT, 16) == 0;

    // create procedure
    if (isLinkedit) {
      procedures.emplace_back(dataHead, eCtx.leTracker->getData(),
                              seg.command->filesize);
    } else {
      procedures.emplace_back(dataHead, mCtx.convertAddrP(seg.command->vmaddr),
                              seg.command->filesize);

      if (writeExObjc && eCtx.exObjc &&
          strncmp(eCtx.exObjc->getExtendsSeg().c_str(), seg.command->segname,
                  16) == 0) {
        // add procedure for ExObjc and increase size of segment
        auto &exObjc = eCtx.exObjc.value();
        auto exObjcStart = exObjc.getBaseAddr();
        auto exObjcEnd = exObjc.getEndAddr();
        procedures.emplace_back(dataHead + (exObjcStart - seg.command->vmaddr),
                                exObjc.getData(), exObjcEnd - exObjcStart);

        auto newSize = exObjcEnd - seg.command->vmaddr;
        seg.command->vmsize = newSize;
        seg.command->filesize = newSize;
      }
    }

    // shift the segment and sections
    int32_t shiftDelta = dataHead - (uint32_t)seg.command->fileoff;
    seg.command->fileoff += shiftDelta;
    for (auto &section : seg.sections) {
      section->offset += shiftDelta;
    }

    if (isLinkedit) {
      eCtx.leTracker->changeOffset((uint32_t)seg.command->fileoff);
    }

    // update and page align dataHead
    dataHead += (uint32_t)seg.command->filesize;
    Utils::align(&dataHead, SEGMENT_ALIGNMENT);
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
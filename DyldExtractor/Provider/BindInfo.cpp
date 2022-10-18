#include "BindInfo.h"

#include <Utils/Architectures.h>
#include <Utils/Leb128.h>
#include <fmt/core.h>
#include <functional>

using namespace DyldExtractor;
using namespace Provider;

struct IntermediateBindRecord {
  uint8_t segIndex = 0;
  uint64_t segOffset = 0;
  uint8_t type = 0;
  uint8_t flags = 0;
  int libOrdinal = 0;
  char *symbolName = nullptr;
  int64_t addend = 0;
};

/// @brief Bind info reader implementation
/// @param start Pointer to start of opcode stream.
/// @param end Pointer to end of opcode stream.
/// @param callback Called for each bind record. The first argument is the
/// offset of the bind record from the start of the stream, which only makes
/// sense for lazy bind info. Return false to stop reading.
template <class P>
void readBindStream(
    const uint8_t *const start, const uint8_t *const end, bool stopAtDone,
    std::function<bool(uint32_t, IntermediateBindRecord)> callback) {
  const uint8_t *currentRecordStart = start;
  IntermediateBindRecord currentRecord;

  const uint32_t ptrSize = sizeof(P::PtrT);
  const uint8_t *p = start;

  while (p < end) {
    const auto opcode = *p & BIND_OPCODE_MASK;
    const auto imm = *p & BIND_IMMEDIATE_MASK;
    p++;

    switch (opcode) {
    case BIND_OPCODE_DONE:
      if (stopAtDone) {
        return;
      } else {
        // Resets and starts a new record
        currentRecord = IntermediateBindRecord();
        currentRecordStart = p;
      }
      break;

    case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
      currentRecord.libOrdinal = imm;
      break;

    case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
      currentRecord.libOrdinal = (int)Utils::readUleb128(p, end);
      break;

    case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
      // the special ordinals are negative numbers
      if (imm == 0)
        currentRecord.libOrdinal = 0;
      else {
        int8_t signExtended = BIND_OPCODE_MASK | imm;
        currentRecord.libOrdinal = signExtended;
      }
      break;

    case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
      currentRecord.flags = imm;
      currentRecord.symbolName = (char *)p;
      while (*p != '\0')
        p++;
      p++;
      break;

    case BIND_OPCODE_SET_TYPE_IMM:
      currentRecord.type = imm;
      break;

    case BIND_OPCODE_SET_ADDEND_SLEB:
      currentRecord.addend = Utils::readSleb128(p, end);
      break;

    case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      currentRecord.segIndex = imm;
      currentRecord.segOffset = Utils::readUleb128(p, end);
      break;

    case BIND_OPCODE_ADD_ADDR_ULEB:
      currentRecord.segOffset += Utils::readUleb128(p, end);
      break;

    case BIND_OPCODE_DO_BIND:
      if (!callback((uint32_t)(currentRecordStart - start), currentRecord)) {
        return;
      }

      currentRecord.segOffset += ptrSize;
      break;

    case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
      if (!callback((uint32_t)(currentRecordStart - start), currentRecord)) {
        return;
      }

      currentRecord.segOffset += Utils::readUleb128(p, end) + ptrSize;
      break;

    case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
      if (!callback((uint32_t)(currentRecordStart - start), currentRecord)) {
        return;
      }

      currentRecord.segOffset += imm * ptrSize + ptrSize;
      break;

    case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
      const auto count = Utils::readUleb128(p, end);
      const auto skip = Utils::readUleb128(p, end);
      for (uint32_t i = 0; i < count; i++) {
        if (!callback((uint32_t)(currentRecordStart - start), currentRecord)) {
          return;
        }

        currentRecord.segOffset += skip + ptrSize;
      }
      break;
    }

    default:
      throw std::invalid_argument(
          fmt::format("Unknown bind opcode 0x{:02x}", *p));
    }
  }
}

template <class P>
BindInfo<P>::BindInfo(const Macho::Context<false, P> &mCtx) : mCtx(&mCtx) {
  linkeditFile =
      mCtx.convertAddr(mCtx.getSegment(SEG_LINKEDIT)->command->vmaddr).second;
  dyldInfo = mCtx.getFirstLC<Macho::Loader::dyld_info_command>();
}

template <class P> const std::vector<BindRecord> &BindInfo<P>::getBinds() {
  if (!readStatus.bind) {
    readBinds();
  }

  return binds;
}

template <class P> const std::vector<BindRecord> &BindInfo<P>::getWeakBinds() {
  if (!readStatus.weak) {
    readWeakBinds();
  }

  return weakBinds;
}

template <class P>
const std::map<uint32_t, BindRecord> &BindInfo<P>::getLazyBinds() {
  if (!readStatus.lazy) {
    readLazyBinds();
  }

  return lazyBinds;
}

template <class P> const BindRecord *BindInfo<P>::getLazyBind(uint32_t offset) {
  if (!readStatus.lazy) {
    readLazyBinds();
  }

  if (lazyBinds.contains(offset)) {
    return &lazyBinds.at(offset);
  } else {
    return nullptr;
  }
}

template <class P> bool BindInfo<P>::hasLazyBinds() const {
  return dyldInfo != nullptr && dyldInfo->lazy_bind_size != 0;
}

template <class P> void BindInfo<P>::readBinds() {
  if (readStatus.bind) {
    return;
  }

  if (!dyldInfo || !dyldInfo->bind_size) {
    readStatus.bind = true;
    return;
  }

  auto bindStart = linkeditFile + dyldInfo->bind_off;
  auto bindEnd = bindStart + dyldInfo->bind_size;
  readBindStream<P>(bindStart, bindEnd, true,
                    [this](uint32_t, IntermediateBindRecord record) {
                      binds.emplace_back(
                          mCtx->segments.at(record.segIndex).command->vmaddr +
                              record.segOffset,
                          record.type, record.flags, record.libOrdinal,
                          record.symbolName, record.addend);
                      return true;
                    });

  readStatus.bind = true;
}

template <class P> void BindInfo<P>::readWeakBinds() {
  if (readStatus.weak) {
    return;
  }

  if (!dyldInfo || !dyldInfo->weak_bind_size) {
    readStatus.weak = true;
    return;
  }

  auto bindStart = linkeditFile + dyldInfo->weak_bind_off;
  auto bindEnd = bindStart + dyldInfo->weak_bind_size;
  readBindStream<P>(bindStart, bindEnd, true,
                    [this](uint32_t, IntermediateBindRecord record) {
                      weakBinds.emplace_back(
                          mCtx->segments.at(record.segIndex).command->vmaddr +
                              record.segOffset,
                          record.type, record.flags, record.libOrdinal,
                          record.symbolName, record.addend);
                      return true;
                    });

  readStatus.weak = true;
}

template <class P> void BindInfo<P>::readLazyBinds() {
  if (readStatus.lazy) {
    return;
  }

  if (!dyldInfo || !dyldInfo->lazy_bind_size) {
    readStatus.lazy = true;
    return;
  }

  auto bindStart = linkeditFile + dyldInfo->lazy_bind_off;
  auto bindEnd = bindStart + dyldInfo->lazy_bind_size;
  readBindStream<P>(
      bindStart, bindEnd, false,
      [this](uint32_t off, IntermediateBindRecord record) {
        lazyBinds.emplace(
            off, BindRecord{mCtx->segments.at(record.segIndex).command->vmaddr +
                                record.segOffset,
                            record.type, record.flags, record.libOrdinal,
                            record.symbolName, record.addend});
        return true;
      });

  readStatus.lazy = true;
}

template class BindInfo<Utils::Arch::Pointer32>;
template class BindInfo<Utils::Arch::Pointer64>;
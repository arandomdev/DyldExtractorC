#include "BindInfo.h"

#include <Utils/Architectures.h>
#include <Utils/Uleb128.h>
#include <fmt/core.h>
#include <stdexcept>

using namespace Macho;

template <class P>
Generator<BindRecord> Macho::BindInfoReader(const uint8_t *start,
                                            const uint8_t *end) {
  BindRecord currentRecord;
  const uint32_t ptrSize = sizeof(P::PtrT);
  const uint8_t *p = start;

  while (p < end) {
    const auto opcode = *p & BIND_OPCODE_MASK;
    const auto imm = *p & BIND_IMMEDIATE_MASK;
    p++;

    switch (opcode) {
    case BIND_OPCODE_DONE:
      // Only resets the record apparently
      currentRecord = BindRecord();
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
      co_yield currentRecord;
      currentRecord.segOffset += ptrSize;
      break;

    case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
      co_yield currentRecord;
      currentRecord.segOffset += Utils::readUleb128(p, end) + ptrSize;
      break;

    case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
      co_yield currentRecord;
      currentRecord.segOffset += imm * ptrSize + ptrSize;
      break;

    case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
      const auto count = Utils::readUleb128(p, end);
      const auto skip = Utils::readUleb128(p, end);
      for (uint32_t i = 0; i < count; i++) {
        co_yield currentRecord;
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

template Generator<BindRecord>
Macho::BindInfoReader<Utils::Pointer32>(const uint8_t *start,
                                        const uint8_t *end);
template Generator<BindRecord>
Macho::BindInfoReader<Utils::Pointer64>(const uint8_t *start,
                                        const uint8_t *end);
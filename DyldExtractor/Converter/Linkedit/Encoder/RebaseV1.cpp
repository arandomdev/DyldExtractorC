#include "RebaseV1.h"

#include "Utils/Leb128.h"

using namespace DyldExtractor;
using namespace Converter;
using namespace Linkedit;
using namespace Encoder;

RebaseV1Info::RebaseV1Info(uint8_t t, uint64_t addr)
    : _type(t), _address(addr) {}

struct rebase_tmp {
  rebase_tmp(uint8_t op, uint64_t p1, uint64_t p2 = 0)
      : opcode(op), operand1(p1), operand2(p2) {}
  uint8_t opcode;
  uint64_t operand1;
  uint64_t operand2;
};

template <typename P>
std::vector<uint8_t>
Encoder::encodeRebaseV1(const std::vector<RebaseV1Info> &info,
                        const Macho::Context<false, P> &mCtx) {
  using PtrT = P::PtrT;

  // convert to temp encoding that can be more easily optimized
  std::vector<rebase_tmp> mid;
  uint64_t curSegStart = 0;
  uint64_t curSegEnd = 0;
  uint32_t curSegIndex = 0;
  uint8_t type = 0;
  uint64_t address = (uint64_t)(-1);
  for (auto it = info.begin(); it != info.end(); ++it) {
    if (type != it->_type) {
      mid.push_back(rebase_tmp(REBASE_OPCODE_SET_TYPE_IMM, it->_type));
      type = it->_type;
    }
    if (address != it->_address) {
      if ((it->_address < curSegStart) || (it->_address >= curSegEnd)) {

        // Find segment containing address
        bool found = false;
        for (int segI = 0; segI < mCtx.segments.size(); segI++) {
          const auto &seg = mCtx.segments.at(segI);

          if ((it->_address < seg.command->vmaddr) ||
              (it->_address >= (seg.command->vmaddr + seg.command->vmsize))) {
            curSegStart = seg.command->vmaddr;
            curSegEnd = seg.command->vmaddr + seg.command->vmsize;
            curSegIndex = segI;
            found = true;
            break;
          }
        }
        if (!found)
          throw "binding address outside range of any segment";

        mid.push_back(rebase_tmp(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
                                 curSegIndex, it->_address - curSegStart));
      } else {
        mid.push_back(
            rebase_tmp(REBASE_OPCODE_ADD_ADDR_ULEB, it->_address - address));
      }
      address = it->_address;
    }
    mid.push_back(rebase_tmp(REBASE_OPCODE_DO_REBASE_ULEB_TIMES, 1));
    address += sizeof(PtrT);
    if (address >= curSegEnd)
      address = 0;
  }
  mid.push_back(rebase_tmp(REBASE_OPCODE_DONE, 0));

  // optimize phase 1, compress packed runs of pointers
  rebase_tmp *dst = &mid[0];
  for (const rebase_tmp *src = &mid[0]; src->opcode != REBASE_OPCODE_DONE;
       ++src) {
    if ((src->opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES) &&
        (src->operand1 == 1)) {
      *dst = *src++;
      while (src->opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES) {
        dst->operand1 += src->operand1;
        ++src;
      }
      --src;
      ++dst;
    } else {
      *dst++ = *src;
    }
  }
  dst->opcode = REBASE_OPCODE_DONE;

  // optimize phase 2, combine rebase/add pairs
  dst = &mid[0];
  for (const rebase_tmp *src = &mid[0]; src->opcode != REBASE_OPCODE_DONE;
       ++src) {
    if ((src->opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES) &&
        (src->operand1 == 1) &&
        (src[1].opcode == REBASE_OPCODE_ADD_ADDR_ULEB)) {
      dst->opcode = REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB;
      dst->operand1 = src[1].operand1;
      ++src;
      ++dst;
    } else {
      *dst++ = *src;
    }
  }
  dst->opcode = REBASE_OPCODE_DONE;

  // optimize phase 3, compress packed runs of
  // REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB with same addr delta into one
  // REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
  dst = &mid[0];
  for (const rebase_tmp *src = &mid[0]; src->opcode != REBASE_OPCODE_DONE;
       ++src) {
    uint64_t delta = src->operand1;
    if ((src->opcode == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB) &&
        (src[1].opcode == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB) &&
        (src[2].opcode == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB) &&
        (src[1].operand1 == delta) && (src[2].operand1 == delta)) {
      // found at least three in a row, this is worth compressing
      dst->opcode = REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB;
      dst->operand1 = 1;
      dst->operand2 = delta;
      ++src;
      while ((src->opcode == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB) &&
             (src->operand1 == delta)) {
        dst->operand1++;
        ++src;
      }
      --src;
      ++dst;
    } else {
      *dst++ = *src;
    }
  }
  dst->opcode = REBASE_OPCODE_DONE;

  // optimize phase 4, use immediate encodings
  for (rebase_tmp *p = &mid[0]; p->opcode != REBASE_OPCODE_DONE; ++p) {
    if ((p->opcode == REBASE_OPCODE_ADD_ADDR_ULEB) &&
        (p->operand1 < (15 * sizeof(PtrT))) &&
        ((p->operand1 % sizeof(PtrT)) == 0)) {
      p->opcode = REBASE_OPCODE_ADD_ADDR_IMM_SCALED;
      p->operand1 = p->operand1 / sizeof(PtrT);
    } else if ((p->opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES) &&
               (p->operand1 < 15)) {
      p->opcode = REBASE_OPCODE_DO_REBASE_IMM_TIMES;
    }
  }

  // convert to compressed encoding
  std::vector<uint8_t> encodedData;
  encodedData.reserve(info.size() * 2);
  bool done = false;
  for (auto it = mid.begin(); !done && it != mid.end(); ++it) {
    switch (it->opcode) {
    case REBASE_OPCODE_DONE:

      done = true;
      break;
    case REBASE_OPCODE_SET_TYPE_IMM:

      encodedData.push_back(
          (uint8_t)(REBASE_OPCODE_SET_TYPE_IMM | it->operand1));
      break;
    case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:

      encodedData.push_back(
          (uint8_t)(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | it->operand1));
      Utils::appendUleb128(encodedData, it->operand2);
      break;
    case REBASE_OPCODE_ADD_ADDR_ULEB:

      encodedData.push_back(REBASE_OPCODE_ADD_ADDR_ULEB);
      Utils::appendUleb128(encodedData, it->operand1);
      break;
    case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:

      encodedData.push_back(
          (uint8_t)(REBASE_OPCODE_ADD_ADDR_IMM_SCALED | it->operand1));
      break;
    case REBASE_OPCODE_DO_REBASE_IMM_TIMES:

      encodedData.push_back(
          (uint8_t)(REBASE_OPCODE_DO_REBASE_IMM_TIMES | it->operand1));
      break;
    case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:

      encodedData.push_back(REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
      Utils::appendUleb128(encodedData, it->operand1);
      break;
    case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:

      encodedData.push_back(REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB);
      Utils::appendUleb128(encodedData, it->operand1);
      break;
    case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:

      encodedData.push_back(REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB);
      Utils::appendUleb128(encodedData, it->operand1);
      Utils::appendUleb128(encodedData, it->operand2);
      break;
    }
  }

  // align to pointer size
  auto padSize =
      Utils::align(encodedData.size(), sizeof(PtrT)) - encodedData.size();
  encodedData.insert(encodedData.end(), padSize, 0x0);
  return encodedData;
}

template std::vector<uint8_t> Encoder::encodeRebaseV1<Utils::Arch::Pointer32>(
    const std::vector<RebaseV1Info> &info,
    const Macho::Context<false, Utils::Arch::Pointer32> &mCtx);
template std::vector<uint8_t> Encoder::encodeRebaseV1<Utils::Arch::Pointer64>(
    const std::vector<RebaseV1Info> &info,
    const Macho::Context<false, Utils::Arch::Pointer64> &mCtx);
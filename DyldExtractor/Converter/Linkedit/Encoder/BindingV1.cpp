#include "BindingV1.h"

#include <Utils/Leb128.h>
#include <Utils/Utils.h>

using namespace DyldExtractor;
using namespace Converter;
using namespace Linkedit;
using namespace Encoder;

BindingV1Info::BindingV1Info(uint8_t _type, uint8_t _flags,
                             uint16_t _threadedBindOrdinal, int _libraryOrdinal,
                             const char *_symbolName, uint64_t _address,
                             int64_t _addend)
    : _type(_type), _flags(_flags), _threadedBindOrdinal(_threadedBindOrdinal),
      _libraryOrdinal(_libraryOrdinal), _symbolName(_symbolName),
      _address(_address), _addend(_addend) {}
BindingV1Info::BindingV1Info(uint8_t t, int ord, const char *sym,
                             bool weak_import, uint64_t addr, int64_t add)
    : _type(t), _flags(weak_import ? BIND_SYMBOL_FLAGS_WEAK_IMPORT : 0),
      _threadedBindOrdinal(0), _libraryOrdinal(ord), _symbolName(sym),
      _address(addr), _addend(add) {}
BindingV1Info::BindingV1Info(uint8_t t, const char *sym,
                             bool non_weak_definition, uint64_t addr,
                             int64_t add)
    : _type(t),
      _flags(non_weak_definition ? BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION : 0),
      _threadedBindOrdinal(0), _libraryOrdinal(0), _symbolName(sym),
      _address(addr), _addend(add) {}

int BindingV1Info::operator<(const BindingV1Info &rhs) const {
  // sort by library, symbol, type, flags, then address
  if (this->_libraryOrdinal != rhs._libraryOrdinal)
    return (this->_libraryOrdinal < rhs._libraryOrdinal);
  if (this->_symbolName != rhs._symbolName)
    return (strcmp(this->_symbolName, rhs._symbolName) < 0);
  if (this->_type != rhs._type)
    return (this->_type < rhs._type);
  if (this->_flags != rhs._flags)
    return (this->_flags >= rhs._flags);
  return (this->_address < rhs._address);
}

struct binding_tmp {
  binding_tmp(uint8_t op, uint64_t p1, uint64_t p2 = 0, const char *s = NULL)
      : opcode(op), operand1(p1), operand2(p2), name(s) {}
  uint8_t opcode;
  uint64_t operand1;
  uint64_t operand2;
  const char *name;
};

template <class P>
std::vector<uint8_t>
Encoder::encodeBindingV1(std::vector<BindingV1Info> &info,
                         const Macho::Context<false, P> &mCtx) {
  using PtrT = P::PtrT;

  // sort by library, symbol, type, then address
  std::sort(info.begin(), info.end());

  // convert to temp encoding that can be more easily optimized
  std::vector<binding_tmp> mid;
  uint64_t curSegStart = 0;
  uint64_t curSegEnd = 0;
  uint32_t curSegIndex = 0;
  int ordinal = 0x80000000;
  const char *symbolName = NULL;
  uint8_t type = 0;
  uint64_t address = (uint64_t)(-1);
  int64_t addend = 0;
  for (auto it = info.begin(); it != info.end(); ++it) {
    if (ordinal != it->_libraryOrdinal) {
      if (it->_libraryOrdinal <= 0) {
        // special lookups are encoded as negative numbers in BindingInfo
        mid.push_back(binding_tmp(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
                                  it->_libraryOrdinal));
      } else {
        mid.push_back(binding_tmp(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
                                  it->_libraryOrdinal));
      }
      ordinal = it->_libraryOrdinal;
    }
    if (symbolName != it->_symbolName) {
      mid.push_back(binding_tmp(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
                                it->_flags, 0, it->_symbolName));
      symbolName = it->_symbolName;
    }
    if (type != it->_type) {
      mid.push_back(binding_tmp(BIND_OPCODE_SET_TYPE_IMM, it->_type));
      type = it->_type;
    }
    if (address != it->_address) {
      if ((it->_address < curSegStart) || (it->_address >= curSegEnd)) {

        // Find segment containing address
        bool found = false;
        for (int segI = 0; segI < mCtx.segments.size(); segI++) {
          const auto &seg = mCtx.segments.at(segI);

          if ((it->_address >= seg.command->vmaddr) &&
              (it->_address < (seg.command->vmaddr + seg.command->vmsize))) {
            curSegStart = seg.command->vmaddr;
            curSegEnd = seg.command->vmaddr + seg.command->vmsize;
            curSegIndex = segI;
            found = true;
            break;
          }
        }
        if (!found)
          throw "binding address outside range of any segment";

        mid.push_back(binding_tmp(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
                                  curSegIndex, it->_address - curSegStart));
      } else {
        mid.push_back(
            binding_tmp(BIND_OPCODE_ADD_ADDR_ULEB, it->_address - address));
      }
      address = it->_address;
    }
    if (addend != it->_addend) {
      mid.push_back(binding_tmp(BIND_OPCODE_SET_ADDEND_SLEB, it->_addend));
      addend = it->_addend;
    }
    mid.push_back(binding_tmp(BIND_OPCODE_DO_BIND, 0));
    address += sizeof(PtrT);
  }
  mid.push_back(binding_tmp(BIND_OPCODE_DONE, 0));

  // optimize phase 1, combine bind/add pairs
  binding_tmp *dst = &mid[0];
  for (const binding_tmp *src = &mid[0]; src->opcode != BIND_OPCODE_DONE;
       ++src) {
    if ((src->opcode == BIND_OPCODE_DO_BIND) &&
        (src[1].opcode == BIND_OPCODE_ADD_ADDR_ULEB)) {
      dst->opcode = BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB;
      dst->operand1 = src[1].operand1;
      ++src;
      ++dst;
    } else {
      *dst++ = *src;
    }
  }
  dst->opcode = BIND_OPCODE_DONE;

  // optimize phase 2, compress packed runs of BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
  // with same addr delta into one BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
  dst = &mid[0];
  for (const binding_tmp *src = &mid[0]; src->opcode != BIND_OPCODE_DONE;
       ++src) {
    uint64_t delta = src->operand1;
    if ((src->opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB) &&
        (src[1].opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB) &&
        (src[1].operand1 == delta)) {
      // found at least two in a row, this is worth compressing
      dst->opcode = BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB;
      dst->operand1 = 1;
      dst->operand2 = delta;
      ++src;
      while ((src->opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB) &&
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
  dst->opcode = BIND_OPCODE_DONE;

  // optimize phase 3, use immediate encodings
  for (binding_tmp *p = &mid[0]; p->opcode != REBASE_OPCODE_DONE; ++p) {
    if ((p->opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB) &&
        (p->operand1 < (15 * sizeof(PtrT))) &&
        ((p->operand1 % sizeof(PtrT)) == 0)) {
      p->opcode = BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED;
      p->operand1 = p->operand1 / sizeof(PtrT);
    } else if ((p->opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB) &&
               (p->operand1 <= 15)) {
      p->opcode = BIND_OPCODE_SET_DYLIB_ORDINAL_IMM;
    }
  }
  dst->opcode = BIND_OPCODE_DONE;

  // convert to compressed encoding
  std::vector<uint8_t> encodedData;
  encodedData.reserve(info.size() * 2);

  bool done = false;
  for (auto it = mid.begin(); !done && it != mid.end(); ++it) {
    switch (it->opcode) {
    case BIND_OPCODE_DONE:

      done = true;
      break;
    case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:

      encodedData.push_back(
          (uint8_t)(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | it->operand1));
      break;
    case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:

      encodedData.push_back(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
      Utils::appendUleb128(encodedData, it->operand1);
      break;
    case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:

      encodedData.push_back((uint8_t)(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM |
                                      (it->operand1 & BIND_IMMEDIATE_MASK)));
      break;
    case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:

      encodedData.push_back(
          (uint8_t)(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | it->operand1));
      for (const char *s = it->name; *s != '\0'; ++s) {
        encodedData.push_back(*s);
      }
      encodedData.push_back('\0');
      break;
    case BIND_OPCODE_SET_TYPE_IMM:

      encodedData.push_back((uint8_t)(BIND_OPCODE_SET_TYPE_IMM | it->operand1));
      break;
    case BIND_OPCODE_SET_ADDEND_SLEB:

      encodedData.push_back(BIND_OPCODE_SET_ADDEND_SLEB);
      Utils::appendSleb128(encodedData, it->operand1);
      break;
    case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:

      encodedData.push_back(
          (uint8_t)(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | it->operand1));
      Utils::appendUleb128(encodedData, it->operand2);
      break;
    case BIND_OPCODE_ADD_ADDR_ULEB:

      encodedData.push_back(BIND_OPCODE_ADD_ADDR_ULEB);
      Utils::appendUleb128(encodedData, it->operand1);
      break;
    case BIND_OPCODE_DO_BIND:

      encodedData.push_back(BIND_OPCODE_DO_BIND);
      break;
    case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:

      encodedData.push_back(BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB);
      Utils::appendUleb128(encodedData, it->operand1);
      break;
    case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:

      encodedData.push_back(
          (uint8_t)(BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED | it->operand1));
      break;
    case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:

      encodedData.push_back(BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB);
      Utils::appendUleb128(encodedData, it->operand1);
      Utils::appendUleb128(encodedData, it->operand2);
      break;
    }
  }

  // align to pointer size
  encodedData.resize(Utils::align(encodedData.size(), sizeof(PtrT)));
  return encodedData;
}

template std::vector<uint8_t> Encoder::encodeBindingV1<Utils::Arch::Pointer32>(
    std::vector<BindingV1Info> &info,
    const Macho::Context<false, Utils::Arch::Pointer32> &mCtx);
template std::vector<uint8_t> Encoder::encodeBindingV1<Utils::Arch::Pointer64>(
    std::vector<BindingV1Info> &info,
    const Macho::Context<false, Utils::Arch::Pointer64> &mCtx);

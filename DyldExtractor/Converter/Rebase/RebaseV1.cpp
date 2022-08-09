/* -*- mode: C++; c-basic-offset: 4; tab-width: 4 -*-*
 *
 * Copyright (c) 2009-2010 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 *
 * This was copied and adapted from ld64, src/ld/LinkEdit.hpp
 */

#include "RebaseV1.h"

#include <Utils/Architectures.h>
#include <Utils/Uleb128.h>
#include <mach-o/loader.h>

using namespace Converter;

struct rebase_tmp {
  rebase_tmp(uint8_t op, uint64_t p1, uint64_t p2 = 0)
      : opcode(op), operand1(p1), operand2(p2) {}
  uint8_t opcode;
  uint64_t operand1;
  uint64_t operand2;
};

template <typename P>
std::vector<uint8_t>
Converter::generateRebaseV1(const std::vector<RebaseV1Info> &info,
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
    if (type != it->type) {
      mid.push_back(rebase_tmp(REBASE_OPCODE_SET_TYPE_IMM, it->type));
      type = it->type;
    }
    if (address != it->address) {
      if ((it->address < curSegStart) || (it->address >= curSegEnd)) {

        // Find segment containing address
        bool found = false;
        for (int segI = 0; segI < mCtx.segments.size(); segI++) {
          const auto &seg = mCtx.segments.at(segI);

          if ((it->address < seg.command->vmaddr) ||
              (it->address >= (seg.command->vmaddr + seg.command->vmsize))) {
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
                                 curSegIndex, it->address - curSegStart));
      } else {
        mid.push_back(
            rebase_tmp(REBASE_OPCODE_ADD_ADDR_ULEB, it->address - address));
      }
      address = it->address;
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

template std::vector<uint8_t> Converter::generateRebaseV1<Utils::Pointer32>(
    const std::vector<RebaseV1Info> &info,
    const Macho::Context<false, Utils::Pointer32> &mCtx);
template std::vector<uint8_t> Converter::generateRebaseV1<Utils::Pointer64>(
    const std::vector<RebaseV1Info> &info,
    const Macho::Context<false, Utils::Pointer64> &mCtx);
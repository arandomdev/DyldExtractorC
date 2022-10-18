#include "ArmUtils.h"

using namespace DyldExtractor;
using namespace Converter;
using namespace Stubs;

ArmUtils::ArmUtils(Utils::ExtractionContext<A> &eCtx)
    : dCtx(*eCtx.dCtx), accelerator(*eCtx.accelerator),
      ptrTracker(eCtx.ptrTracker) {
  stubResolvers = {
      {StubFormat::normalV4, [this](PtrT a) { return getNormalV4Target(a); }},
      {StubFormat::optimizedV5,
       [this](PtrT a) { return getOptimizedV5Target(a); }},
      {StubFormat::resolver, [this](PtrT a) { return getResolverTarget(a); }}};
}

std::optional<ArmUtils::StubBinderInfo>
ArmUtils::isStubBinder(const PtrT addr) const {
  /**
   * 29d8b2bc 04 c0 2d e5 str r12,[sp,#local_4]!
   * 29d8b2c0 10 c0 9f e5 ldr r12,[DAT_29d8b2d8]
   * 29d8b2c4 0c c0 8f e0 add r12,pc,r12
   * 29d8b2c8 04 c0 2d e5 str r12=>PTR_2ef24004,[sp,#local_8]!
   * 29d8b2cc 08 c0 9f e5 ldr r12,[DAT_29d8b2dc]
   * 29d8b2d0 0c c0 8f e0 add r12,pc,r12
   * 29d8b2d4 00 f0 9c e5 ldr pc=>__nl_symbol_ptr::dyld_stub_binder,[r12,#0x0]
   * 29d8b2d8 38 8d 19 05 undefined4 05198D38h -> __dyld_private
   * 29d8b2dc 28 8d 19 05 undefined4 05198D28h -> dyld_stub_binder
   */

  auto plainAddr = addr & -4;
  const auto p = (const uint32_t *)dCtx.convertAddrP(plainAddr);
  if (p == nullptr) {
    return std::nullopt;
  }

  const auto str = p[0];
  const auto ldr = p[1];
  const auto add = p[2];
  const auto str2 = p[3];
  const auto ldr2 = p[4];
  const auto add2 = p[5];
  const auto ldr3 = p[6];
  if ((str & 0x0E500000) != 0x04000000 || (ldr & 0x0F7F0000) != 0x051F0000 ||
      (add & 0x0FE00010) != 0x00800000 || (str2 & 0x0E500000) != 0x04000000 ||
      (ldr2 & 0x0F7F0000) != 0x051F0000 || (add2 & 0x0FE00010) != 0x00800000 ||
      (ldr3 & 0x0E500000) != 0x04100000) {
    return std::nullopt;
  } else {
    const auto privPtrOffset = p[7];
    return StubBinderInfo{plainAddr + 8 + 8 + privPtrOffset, 0x24};
  }
}

std::optional<ArmUtils::PtrT>
ArmUtils::getStubHelperData(const PtrT addr) const {
  /**
   * 29d8b2f8 00 c0 9f e5 ldr r12,[DAT_29d8b300]
   * 29d8b2fc ee ff ff ea b   stub_helpers
   * 29d8b300 39 00 00 00 undefined4 00000039h
   */

  const auto p = (const uint32_t *)dCtx.convertAddrP(addr & -4);
  if (p == nullptr) {
    return std::nullopt;
  }

  const auto ldr = p[0];
  const auto b = p[1];
  if (ldr != 0x0E59FC000 || (b & 0x0F000000) != 0x0A000000) {
    return std::nullopt;
  }

  return p[2];
}

std::optional<ArmUtils::ResolverData>
ArmUtils::getResolverData(const PtrT addr) const {
  /**
   * 20b159f8 0f402de9 stmdb sp!,{r0 r1 r2 r3 lr}
   * 20b159fc d858fefa blx   _vDSP_FFTCSBFirst4S
   * 20b15a00 10c09fe5 ldr   r12,[DAT_20b15a18]
   * 20b15a04 0cc08fe0 add   r12,pc,r12
   * 20b15a08 00008ce5 str   r0,[r12,#0x0]=>__la_symbol_ptr::<redacted>
   * 20b15a0c 00c0a0e1 cpy   r12,r0
   * 20b15a10 0f40bde8 ldmia sp!,{r0 r1 r2 r3 lr}=>local_14
   * 20b15a14 1cff2fe1 bx    r12
   * 20b15a18 7877c20c UNK   0CC27778h
   */

  auto plainAddr = addr & -4;
  const auto p = (const uint32_t *)dCtx.convertAddrP(plainAddr);
  if (p == nullptr) {
    return std::nullopt;
  }

  const auto stmdb = p[0];
  const auto blx = p[1];
  const auto ldr = p[2];
  const auto add = p[3];
  const auto str = p[4];
  const auto cpy = p[5];
  const auto ldmia = p[6];
  const auto bx = p[7];
  if ((stmdb & 0x0FD00000) != 0x09000000 || (blx & 0xFE000000) != 0xFA000000 ||
      (ldr & 0x0E500000) != 0x04100000 || (add & 0x0FE00010) != 0x00800000 ||
      (str & 0x0E500000) != 0x04000000 || (cpy & 0x0FEF0FF0) != 0x01A00000 ||
      (ldmia & 0x0FD00000) != 0x08900000 || (bx & 0x0FFFFFF0) != 0x012FFF10) {
    return std::nullopt;
  }
  const auto resolverData = (int32_t)p[8];

  // Get target function
  PtrT targetFunc;
  {
    const uint32_t imm24 = blx & 0x00FFFFFF;
    const bool H = (blx & 0x01000000) >> 24;
    const int32_t imm32 = signExtend<int32_t, 26>((imm24 << 2) | (H << 1));
    targetFunc = plainAddr + 4 + 8 + imm32;
  }

  PtrT targetPtr = plainAddr + 12 + 8 + resolverData;
  PtrT size = 0x24;
  return ResolverData{targetFunc, targetPtr, size};
}

ArmUtils::PtrT ArmUtils::resolveStubChain(const PtrT addr) {
  if (accelerator.armResolvedChains.contains(addr)) {
    return accelerator.armResolvedChains[addr];
  }

  PtrT target = addr;
  while (true) {
    if (auto stubData = resolveStub(target); stubData != std::nullopt) {
      target = stubData->first;
    } else {
      break;
    }
  }

  accelerator.armResolvedChains[addr] = target;

  return target;
}

std::optional<std::pair<ArmUtils::PtrT, ArmUtils::StubFormat>>
ArmUtils::resolveStub(const PtrT addr) const {
  for (auto &[format, resolver] : stubResolvers) {
    if (auto res = resolver(addr); res != std::nullopt) {
      return std::make_pair(*res, format);
    }
  }

  return std::nullopt;
}

std::optional<ArmUtils::PtrT>
ArmUtils::getNormalV4LdrAddr(const PtrT addr) const {
  // Reference getNormalV4Target

  auto plainAddr = addr & -4;
  const auto p = (const uint32_t *)dCtx.convertAddrP(plainAddr);
  if (p == nullptr) {
    return std::nullopt;
  }

  const auto ldr = p[0];
  const auto add = p[1];
  const auto ldr2 = p[2];
  if (ldr != 0xE59FC004 || add != 0xE08FC00C || ldr2 != 0xE59CF000) {
    return std::nullopt;
  }

  const auto stubData = p[3];
  return plainAddr + 12 + stubData;
}

void ArmUtils::writeNormalV4Stub(uint8_t *loc, const PtrT stubAddr,
                                 const PtrT ldrAddr) const {
  /**
   * ldr ip, pc + 12
   * add ip, pc, ip
   * ldr pc, [ip]
   * stub data
   */

  auto p = (uint32_t *)loc;
  p[0] = 0xE59FC004;
  p[1] = 0xE08FC00C;
  p[2] = 0xE59CF000;
  *(int32_t *)(p + 3) = (int32_t)ldrAddr - stubAddr - 12;
}

std::optional<ArmUtils::PtrT>
ArmUtils::getNormalV4Target(const PtrT addr) const {
  /**
   * 04 c0 9f e5 ldr r12,[DAT_00007f18]
   * 0c c0 8f e0 add r12,pc,r12
   * 00 f0 9c e5 ldr pc=>__stub_helper::_NSLog,[r12,#0x0]
   * f0 00 00 00 UNK 000000F0h
   */

  auto plainAddr = addr & -4;
  const auto p = (const uint32_t *)dCtx.convertAddrP(plainAddr);
  if (p == nullptr) {
    return std::nullopt;
  }

  const auto ldr = p[0];
  const auto add = p[1];
  const auto ldr2 = p[2];
  if (ldr != 0xE59FC004 || add != 0xE08FC00C || ldr2 != 0xE59CF000) {
    return std::nullopt;
  }

  const auto stubData = p[3];
  return ptrTracker.slideP(plainAddr + 12 + stubData);
}

std::optional<ArmUtils::PtrT>
ArmUtils::getOptimizedV5Target(const PtrT addr) const {
  /**
   * 576a3a28 00 c0 9f e5 ldr r12,[DAT_576a3a30]
   * 576a3a2c 0c f0 8f e0 add pc=>LAB_4692f7c4,pc,r12
   * 576a3a30 91 bd 28 ef UNK EF28BD91h
   * 576a3a34 fe de ff e7 udf #0xfdee TRAP
   */

  auto plainAddr = addr & -4;
  const auto p = (const uint32_t *)dCtx.convertAddrP(plainAddr);
  if (p == nullptr) {
    return std::nullopt;
  }

  const auto ldr = p[0];
  const auto add = p[1];
  const auto trap = p[3];
  if (ldr != 0xE59FC000 || add != 0xE08FF00C || trap != 0xE7FFDEFE) {
    return std::nullopt;
  }

  const auto stubData = p[2];

  return (plainAddr + 12 + stubData);
}

std::optional<ArmUtils::PtrT>
ArmUtils::getResolverTarget(const PtrT addr) const {
  if (const auto res = getResolverData(addr); res) {
    return res->targetFunc;
  } else {
    return std::nullopt;
  }
}
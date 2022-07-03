#include "Arm64Utils.h"

using namespace Converter;

Arm64Utils::Arm64Utils(const Utils::ExtractionContext<P> &eCtx)
    : dCtx(eCtx.dCtx), ptrTracker(eCtx.pointerTracker),
      accelerator(eCtx.accelerator) {

  stubResolvers = {
      {StubFormat::StubNormal,
       [this](uint64_t a) { return getStubNormalTarget(a); }},
      {StubFormat::StubOptimized,
       [this](uint64_t a) { return getStubOptimizedTarget(a); }},
      {StubFormat::AuthStubNormal,
       [this](uint64_t a) { return getAuthStubNormalTarget(a); }},
      {StubFormat::AuthStubOptimized,
       [this](uint64_t a) { return getAuthStubOptimizedTarget(a); }},
      {StubFormat::AuthStubResolver,
       [this](uint64_t a) { return getAuthStubResolverTarget(a); }},
      {StubFormat::Resolver,
       [this](uint64_t a) { return getResolverTarget(a); }}};
}

bool Arm64Utils::isStubBinder(const uint64_t addr) const {
  /**
   *  adrp  x17,0x1cb662000
   *  add   x17,x17,#0x2f8
   *  stp   x16,x17=>__dyld_private,[sp, #Stack[-0x10]]!
   *  adrp  x16,0x1c7b40000
   *  ldr   x16,[x16, #offset ->__got::dyld_stub_binder] = 1c7b407d0
   *  br    x16=>__got::dyld_stub_binder
   **/

  const auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return false;
  }

  const auto adrp = p[0];
  const auto add = p[1];
  const auto stp = p[2];
  const auto adrp2 = p[3];
  const auto ldr = p[4];
  const auto br = p[5];

  if ((adrp & 0x9F000000) != 0x90000000 || (add & 0xFFC00000) != 0x91000000 ||
      (stp & 0x7FC00000) != 0x29800000 || (adrp2 & 0x9F000000) != 0x90000000 ||
      (ldr & 0xFFC00000) != 0xF9400000 || br != 0xD61F0200) {
    return false;
  } else {
    return true;
  }
}

std::optional<Arm64Utils::ResolverData>
Arm64Utils::getResolverData(const uint64_t addr) const {
  /**
   * fd 7b bf a9  stp     x29,x30,[sp, #local_10]!
   * fd 03 00 91  mov     x29,sp
   * e1 03 bf a9  stp     x1,x0,[sp, #local_20]!
   * e3 0b bf a9  stp     x3,x2,[sp, #local_30]!
   * e5 13 bf a9  stp     x5,x4,[sp, #local_40]!
   * e7 1b bf a9  stp     x7,x6,[sp, #local_50]!
   * e1 03 bf 6d  stp     d1,d0,[sp, #local_60]!
   * e3 0b bf 6d  stp     d3,d2,[sp, #local_70]!
   * e5 13 bf 6d  stp     d5,d4,[sp, #local_80]!
   * e7 1b bf 6d  stp     d7,d6,[sp, #local_90]!
   * 5f d4 fe 97  bl      _vDSP_vadd
   * 70 e6 26 90  adrp    x16,0x1e38ba000
   * 10 02 0f 91  add     x16,x16,#0x3c0
   * 00 02 00 f9  str     x0,[x16]=>__la_resolver
   * f0 03 00 aa  mov     x16,x0
   * e7 1b c1 6c  ldp     d7,d6,[sp], #0x10
   * e5 13 c1 6c  ldp     d5,d4,[sp], #0x10
   * e3 0b c1 6c  ldp     d3,d2,[sp], #0x10
   * e1 03 c1 6c  ldp     d1,d0,[sp], #0x10
   * e7 1b c1 a8  ldp     x7,x6,[sp], #0x10
   * e5 13 c1 a8  ldp     x5,x4,[sp], #0x10
   * e3 0b c1 a8  ldp     x3,x2,[sp], #0x10
   * e1 03 c1 a8  ldp     x1,x0,[sp], #0x10
   * fd 7b c1 a8  ldp     x29=>local_10,x30,[sp], #0x10
   * 1f 0a 1f d6  braaz   x16

   * Because the format is not the same across iOS versions,
   * the following conditions are used to verify it.
   * * Starts with stp and mov
   * * A branch within an arbitrary threshold
   * * bl is in the middle
   * * adrp, add, and str are directly after bl
   * * ldp is directly before the branch
   */

  const auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return std::nullopt;
  }

  // Test stp and mov
  const auto stp = p[0];
  const auto mov = p[1];
  if ((stp & 0x7FC00000) != 0x29800000 || (mov & 0x7F3FFC00) != 0x11000000) {
    return std::nullopt;
  }

  // Find braaz instruction
  static const uint64_t SEARCH_LIMIT = 50; // 50 instructions
  const uint32_t *braazInstr = nullptr;
  for (auto i = p + 2; i < p + SEARCH_LIMIT; i++) {
    if ((*i & 0xFE9FF000) == 0xD61F0000) {
      braazInstr = i;
      break;
    }
  }
  if (braazInstr == nullptr) {
    return std::nullopt;
  }

  // Find bl instruction
  const uint32_t *blInstr = nullptr;
  for (auto i = p + 2; i < braazInstr; i++) {
    if ((*i & 0xFC000000) == 0x94000000) {
      blInstr = i;
      break;
    }
  }
  if (blInstr == nullptr) {
    return std::nullopt;
  }

  // Test ldp before braaz, adrp, add, and str
  const auto ldp = *(braazInstr - 1);
  const auto adrp = *(blInstr + 1);
  const auto add = *(blInstr + 2);
  const auto str = *(blInstr + 3);
  if ((ldp & 0x7FC00000) != 0x28C00000 || (adrp & 0x9F00001F) != 0x90000010 ||
      (add & 0xFFC00000) != 0x91000000 || (str & 0xFFC00000) != 0xF9000000) {
    return std::nullopt;
  }

  // Hopefully it's a resolver, first get function target
  uint64_t blResult;
  {
    const int64_t imm = signExtend<int64_t, 28>((*blInstr & 0x3FFFFFF) << 2);
    blResult = addr + ((blInstr - p) * 4) + imm;
  }

  // Get pointer
  uint64_t adrpResult;
  {
    const uint64_t immlo = (adrp & 0x60000000) >> 29;
    const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
    const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
    adrpResult = (addr & ~0xFFF) + imm;
  }
  uint64_t addResult;
  {
    const uint64_t addImm = (add & 0x3FFC00) >> 10;
    addResult = adrpResult + addImm;
  }
  uint64_t strResult;
  {
    const int64_t imm12 = signExtend<int64_t, 12>(str & 0x3FFC00);
    strResult = addResult + imm12;
  }

  const uint64_t size = ((braazInstr - p) * 4) + 4;
  return ResolverData{blResult, strResult, size};
}

std::optional<std::pair<uint64_t, Arm64Utils::StubFormat>>
Arm64Utils::resolveStub(const uint64_t addr) const {
  for (auto &[format, resolver] : stubResolvers) {
    if (auto res = resolver(addr); res != std::nullopt) {
      return std::make_pair(*res, format);
    }
  }

  return std::nullopt;
}

uint64_t Arm64Utils::resolveStubChain(const uint64_t addr) {
  if (accelerator.arm64ResolvedChains.contains(addr)) {
    return accelerator.arm64ResolvedChains[addr];
  }

  uint64_t target = addr;
  while (true) {
    if (auto stubData = resolveStub(target); stubData != std::nullopt) {
      target = stubData->first;
    } else {
      break;
    }
  }

  resolvedChains[addr] = target;
  accelerator.arm64ResolvedChains[addr] = target;

  return target;
}

std::optional<uint64_t>
Arm64Utils::getStubHelperData(const uint64_t addr) const {
  auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return std::nullopt;
  }

  // Verify
  const auto ldr = p[0];
  const auto b = p[1];
  if ((ldr & 0xBF000000) != 0x18000000 || (b & 0xFC000000) != 0x14000000) {
    return std::nullopt;
  }

  return p[2];
}

std::optional<uint64_t> Arm64Utils::getStubLdrAddr(const uint64_t addr) const {
  const auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return std::nullopt;
  }

  // Verify
  const auto adrp = p[0];
  const auto ldr = p[1];
  const auto br = p[2];
  if ((adrp & 0x9F00001F) != 0x90000010 || (ldr & 0xFFC003FF) != 0xF9400210 ||
      br != 0xD61F0200) {
    return std::nullopt;
  }

  // adrp
  const uint64_t immlo = (adrp & 0x60000000) >> 29;
  const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
  const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
  const uint64_t adrpResult = (addr & ~0xFFF) + imm;

  // ldr
  const uint64_t offset = (ldr & 0x3FFC00) >> 7;
  return adrpResult + offset;
}

std::optional<uint64_t>
Arm64Utils::getAuthStubLdrAddr(const uint64_t addr) const {
  const auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return std::nullopt;
  }

  // Verify
  const auto adrp = p[0];
  const auto add = p[1];
  const auto ldr = p[2];
  const auto braa = p[3];
  if ((adrp & 0x9F000000) != 0x90000000 || (add & 0xFFC00000) != 0x91000000 ||
      (ldr & 0xFFC00000) != 0xF9400000 || (braa & 0xFEFFF800) != 0xD61F0800) {
    return std::nullopt;
  }

  // adrp
  const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
  const uint64_t immlo = (adrp & 0x60000000) >> 29;
  const int64_t adrpImm = signExtend<int64_t, 33>((immhi | immlo) << 12);
  const uint64_t adrpResult = (addr & ~0xFFF) + adrpImm;

  // add
  const uint64_t addImm = (add & 0x3FFC00) >> 10;
  const uint64_t addResult = adrpResult + addImm;

  // ldr
  const uint64_t ldrImm = (ldr & 0x3FFC00) >> 7;
  return addResult + ldrImm;
}

void Arm64Utils::writeNormalStub(uint8_t *loc, const uint64_t stubAddr,
                                 const uint64_t ldrAddr) const {
  auto instructions = (uint32_t *)loc;

  // ADRP X16, lp@page
  const uint64_t adrpDelta = (ldrAddr & -4096) - (stubAddr & -4096);
  const uint64_t immhi = (adrpDelta >> 9) & (0x00FFFFE0);
  const uint64_t immlo = (adrpDelta << 17) & (0x60000000);
  instructions[0] = (uint32_t)((0x90000010) | immlo | immhi);

  // LDR X16, [X16, lp@pageoff]
  const uint64_t ldrOffset = ldrAddr - (ldrAddr & -4096);
  const uint64_t imm12 = (ldrOffset << 7) & 0x3FFC00;
  instructions[1] = (uint32_t)(0xF9400210 | imm12);

  // BR X16
  instructions[2] = 0xD61F0200;
}

void Arm64Utils::writeNormalAuthStub(uint8_t *loc, const uint64_t stubAddr,
                                     const uint64_t ldrAddr) const {
  auto instructions = (uint32_t *)loc;

  // ADRP X17, sp@page
  const uint64_t adrpDelta = (ldrAddr & -4096) - (stubAddr & -4096);
  const uint64_t immhi = (adrpDelta >> 9) & (0x00FFFFE0);
  const uint64_t immlo = (adrpDelta << 17) & (0x60000000);
  instructions[0] = (uint32_t)((0x90000011) | immlo | immhi);

  // ADD X17, [X17, sp@pageoff]
  const uint64_t addOffset = ldrAddr - (ldrAddr & -4096);
  const uint64_t imm12 = (addOffset << 10) & 0x3FFC00;
  instructions[1] = (uint32_t)(0x91000231 | imm12);

  // LDR X16, [X17, 0]
  instructions[2] = 0xF9400230;

  // BRAA X16
  instructions[3] = 0xD71F0A11;
}

std::optional<uint64_t>
Arm64Utils::getStubNormalTarget(const uint64_t addr) const {
  /**
   * ADRP x16, page
   * LDR x16, [x16, pageoff] -> [Symbol pointer]
   * BR x16
   */

  const auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return std::nullopt;
  }

  // Verify
  const auto adrp = p[0];
  const auto ldr = p[1];
  const auto br = p[2];
  if ((adrp & 0x9F00001F) != 0x90000010 || (ldr & 0xFFC003FF) != 0xF9400210 ||
      br != 0xD61F0200) {
    return std::nullopt;
  }

  // adrp
  const uint64_t immlo = (adrp & 0x60000000) >> 29;
  const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
  const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
  const uint64_t adrpResult = (addr & ~0xFFF) + imm;

  // ldr
  const uint64_t offset = (ldr & 0x3FFC00) >> 7;
  const uint64_t ldrTarget = adrpResult + offset;
  return ptrTracker.slideP(ldrTarget);
}

std::optional<uint64_t>
Arm64Utils::getStubOptimizedTarget(const uint64_t addr) const {
  /**
   * ADRP x16, page
   * ADD x16, x16, offset
   * BR x16
   */

  const auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return std::nullopt;
  }

  // Verify
  const auto adrp = p[0];
  const auto add = p[1];
  const auto br = p[2];
  if ((adrp & 0x9F00001F) != 0x90000010 || (add & 0xFFC003FF) != 0x91000210 ||
      br != 0xD61F0200) {
    return std::nullopt;
  }

  // adrp
  const uint64_t immlo = (adrp & 0x60000000) >> 29;
  const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
  const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
  const uint64_t adrpResult = (addr & ~0xFFF) + imm;

  // add
  const uint64_t imm12 = (add & 0x3FFC00) >> 10;
  return adrpResult + imm12;
}

std::optional<uint64_t>
Arm64Utils::getAuthStubNormalTarget(const uint64_t addr) const {
  /**
   * 91 59 11 90  adrp    x17,0x1e27e5000
   * 31 22 0d 91  add     x17,x17,#0x348
   * 30 02 40 f9  ldr     x16,[x17]=>->__auth_stubs::_CCRandomCopyBytes
   * 11 0a 1f d7  braa    x16=>__auth_stubs::_CCRandomCopyBytes,x17
   */

  const auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return std::nullopt;
  }

  // Verify
  const auto adrp = p[0];
  const auto add = p[1];
  const auto ldr = p[2];
  const auto braa = p[3];
  if ((adrp & 0x9F000000) != 0x90000000 || (add & 0xFFC00000) != 0x91000000 ||
      (ldr & 0xFFC00000) != 0xF9400000 || (braa & 0xFEFFF800) != 0xD61F0800) {
    return std::nullopt;
  }

  // adrp
  const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
  const uint64_t immlo = (adrp & 0x60000000) >> 29;
  const int64_t adrpImm = signExtend<int64_t, 33>((immhi | immlo) << 12);
  const uint64_t adrpResult = (addr & ~0xFFF) + adrpImm;

  // add
  const uint64_t addImm = (add & 0x3FFC00) >> 10;
  const uint64_t addResult = adrpResult + addImm;

  // ldr
  const uint64_t ldrImm = (ldr & 0x3FFC00) >> 7;
  const uint64_t ldrTarget = addResult + ldrImm;
  return ptrTracker.slideP(ldrTarget);
}

std::optional<uint64_t>
Arm64Utils::getAuthStubOptimizedTarget(const uint64_t addr) const {
  /**
   * 1bfcb5d20 30 47 e2 90  adrp  x16,0x184599000
   * 1bfcb5d24 10 62 30 91  add   x16,x16,#0xc18
   * 1bfcb5d28 00 02 1f d6  br    x16=>LAB_184599c18
   * 1bfcb5d2c 20 00 20 d4  trap
   */

  const auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return std::nullopt;
  }

  // Verify
  const auto adrp = p[0];
  const auto add = p[1];
  const auto br = p[2];
  const auto trap = p[3];
  if ((adrp & 0x9F000000) != 0x90000000 || (add & 0xFFC00000) != 0x91000000 ||
      br != 0xD61F0200 || trap != 0xD4200020) {
    return std::nullopt;
  }

  // adrp
  const uint64_t immlo = (adrp & 0x60000000) >> 29;
  const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
  const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
  const uint64_t adrpResult = (addr & ~0xFFF) + imm;

  const uint64_t imm12 = (add & 0x3FFC00) >> 10;
  return adrpResult + imm12;
}

std::optional<uint64_t>
Arm64Utils::getAuthStubResolverTarget(const uint64_t addr) const {
  /**
   * 70 e6 26 b0  adrp    x16,0x1e38ba000
   * 10 e6 41 f9  ldr     x16,[x16, #0x3c8]
   * 1f 0a 1f d6  braaz   x16=>FUN_195bee070
   */

  const auto p = (const uint32_t *)dCtx.convertAddrP(addr);
  if (p == nullptr) {
    return std::nullopt;
  }

  // Verify
  const auto adrp = p[0];
  const auto ldr = p[1];
  const auto braaz = p[2];
  if ((adrp & 0x9F000000) != 0x90000000 || (ldr & 0xFFC00000) != 0xF9400000 ||
      (braaz & 0xFEFFF800) != 0xD61F0800) {
    return std::nullopt;
  }

  // adrp
  const uint64_t immlo = (adrp & 0x60000000) >> 29;
  const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
  const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
  const uint64_t adrpResult = (addr & ~0xFFF) + imm;

  // ldr
  const uint64_t ldrImm = (ldr & 0x3FFC00) >> 7;
  const uint64_t ldrTarget = adrpResult + ldrImm;
  return ptrTracker.slideP(ldrTarget);
}

std::optional<uint64_t>
Arm64Utils::getResolverTarget(const uint64_t addr) const {
  // get the resolver target and strip away the size
  if (auto res = getResolverData(addr); res != std::nullopt) {
    return res->targetFunc;
  } else {
    return std::nullopt;
  }
}

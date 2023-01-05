#include "Disassembler.h"

#include <Utils/Utils.h>

using namespace DyldExtractor;
using namespace Provider;

template <class A>
Disassembler<A>::Instruction::Instruction(PtrT addr, uint8_t size)
    : address(addr), id(DISASM_INVALID_INSN), size(size) {}

template <class A>
Disassembler<A>::Instruction::Instruction(cs_insn *raw)
    : address((PtrT)raw->address), id(raw->id), size((uint8_t)raw->size),
      opStr(raw->op_str) {}

template <class A>
Disassembler<A>::Disassembler(const Macho::Context<false, P> &mCtx,
                              Provider::ActivityLogger &activity,
                              std::shared_ptr<spdlog::logger> logger,
                              Provider::FunctionTracker<P> &funcTracker)
    : mCtx(&mCtx), activity(&activity), logger(logger),
      funcTracker(&funcTracker) {
  // Create Capstone engine
  cs_err err;
  if constexpr (std::is_same_v<A, Utils::Arch::x86_64>) {
    // x86_64 not supported but allow construction
    return;
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle);
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                       std::is_same_v<A, Utils::Arch::arm64_32>) {
    err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
  } else {
    Utils::unreachable();
  }

  if (err != CS_ERR_OK) {
    throw std::runtime_error("Unable to open Capstone engine.");
  }
}

template <class A> Disassembler<A>::~Disassembler() { cs_close(&handle); }

template <class A>
Disassembler<A>::Disassembler(Disassembler<A> &&o)
    : mCtx(o.mCtx), activity(o.activity), logger(std::move(o.logger)),
      funcTracker(o.funcTracker), instructions(std::move(o.instructions)),
      textData(o.textData), textAddr(o.textAddr), disassembled(o.disassembled),
      handle(o.handle) {
  o.mCtx = nullptr;
  o.activity = nullptr;
  o.funcTracker = nullptr;
  o.textData = nullptr;
  o.textAddr = 0;
  o.disassembled = false;
  o.handle = 0;
}

template <class A>
Disassembler<A> &Disassembler<A>::operator=(Disassembler<A> &&o) {
  this->mCtx = o.mCtx;
  this->activity = o.activity;
  this->logger = std::move(o.logger);
  this->funcTracker = o.funcTracker;
  this->instructions = std::move(o.instructions);
  this->textData = o.textData;
  this->textAddr = o.textAddr;
  this->disassembled = o.disassembled;
  this->handle = o.handle;

  o.mCtx = nullptr;
  o.activity = nullptr;
  o.funcTracker = nullptr;
  o.textData = nullptr;
  o.textAddr = 0;
  o.disassembled = false;
  o.handle = 0;
  return *this;
}

template <class A> void Disassembler<A>::load() {
  if constexpr (std::is_same_v<A, Utils::Arch::x86_64>) {
    throw std::runtime_error("X86_64 disassembly not supported.");
  }

  if (disassembled) {
    return;
  }
  disassembled = true;
  activity->update("Disassembler", "disassembling (will appear frozen)");

  // Get data about text
  auto textSeg = mCtx->getSegment(SEG_TEXT)->command;
  textData = mCtx->convertAddrP(textSeg->vmaddr);
  textAddr = textSeg->vmaddr;

  // read all data in code entries
  auto dataInCodeCmd =
      mCtx->getFirstLC<Macho::Loader::linkedit_data_command>({LC_DATA_IN_CODE});
  if (dataInCodeCmd) {
    auto leFile =
        mCtx->convertAddr(mCtx->getSegment(SEG_LINKEDIT)->command->vmaddr)
            .second;
    data_in_code_entry *start =
        reinterpret_cast<data_in_code_entry *>(leFile + dataInCodeCmd->dataoff);
    data_in_code_entry *end =
        start + (dataInCodeCmd->datasize / sizeof(data_in_code_entry));
    dataInCodeEntries = {start, end};
  }

  // Arm64 should not have data in code
  if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    if (dataInCodeEntries.size() != 0) {
      SPDLOG_LOGGER_WARN(logger, "Unexpected data in code entries for arm64.");
    }
  }

  // Process all functions
  funcTracker->load();
  for (const auto &func : funcTracker->getFunctions()) {
    disasmFunc((uint32_t)(func.address - textAddr), (uint32_t)func.size);
  }
}

template <class A>
Disassembler<A>::ConstInstructionIt
Disassembler<A>::instructionAtAddr(PtrT addr) const {
  if (addr & 0x3) {
    // Must be 4 byte aligned
    return instructions.cend();
  }

  if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    // Must use binary search as instruction sizes are mixed
    auto it = std::lower_bound(instructions.cbegin(), instructions.cend(),
                               Instruction(addr, 4),
                               [](const Instruction &a, const Instruction &b) {
                                 return a.address < b.address;
                               });
    if (it == instructions.cend() || it->address != addr) {
      return instructions.cend();
    } else {
      return it;
    }

  } else if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                       std::is_same_v<A, Utils::Arch::arm64_32>) {
    PtrT index = (addr - instructions.cbegin()->address) / 4;
    if (index >= instructions.size()) {
      return instructions.cend();
    }

    return instructions.cbegin() + index;
  } else {
    Utils::unreachable();
  }
}

template <class A>
Disassembler<A>::ConstInstructionIt Disassembler<A>::instructionsBegin() const {
  return instructions.cbegin();
}

template <class A>
Disassembler<A>::ConstInstructionIt Disassembler<A>::instructionsEnd() const {
  return instructions.cend();
}

template <class A>
void Disassembler<A>::disasmFunc(uint32_t offset, uint32_t size) {
  // Find data in code entries in the function
  auto dataInCodeBegin = dataInCodeEntries.lower_bound({offset, 0, 0});
  auto dataInCodeEnd = dataInCodeEntries.lower_bound({offset + size, 0, 0});

  uint32_t currOff = offset;
  for (auto it = dataInCodeBegin; it != dataInCodeEnd; it++) {
    uint32_t chunkSize = it->offset - currOff;
    disasmChunk(currOff, chunkSize);

    // Add invalid instruction for data in code
    instructions.emplace_back(textAddr + it->offset, (uint8_t)it->length);
    currOff += chunkSize + it->length;
  }

  // Disassemble to the end of the function
  disasmChunk(currOff, size - (currOff - offset));
}

template <class A>
void Disassembler<A>::disasmChunk(uint32_t offset, uint32_t size) {
  uint32_t currOff = offset;
  while (currOff < offset + size) {
    cs_insn *rawInsn;
    auto count =
        cs_disasm(handle, textData + currOff, size - (currOff - offset),
                  textAddr + currOff, 0, &rawInsn);
    if (count == 0) {
      // Recover and try again
      currOff += recover(currOff);
      continue;
    }

    for (int i = 0; i < count; i++) {
      instructions.emplace_back(rawInsn + i);
      currOff += (rawInsn + i)->size;
    }

    cs_free(rawInsn, count);
  }
}

template <class A> uint32_t Disassembler<A>::recover(uint32_t offset) {
  if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    instructions.emplace_back(textAddr + offset, 2);
    return 2;
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                       std::is_same_v<A, Utils::Arch::arm64_32>) {
    instructions.emplace_back(textAddr + offset, 4);
    return 4;
  } else {
    Utils::unreachable();
  }
}

template class Disassembler<Utils::Arch::x86_64>;
template class Disassembler<Utils::Arch::arm>;
template class Disassembler<Utils::Arch::arm64>;
template class Disassembler<Utils::Arch::arm64_32>;
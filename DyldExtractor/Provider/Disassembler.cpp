#include "Disassembler.h"

using namespace Provider;
#define INVALID_INSN 0

template <class A>
Disassembler<A>::Instruction::Instruction(PtrT addr, uint8_t size)
    : address(addr), id(INVALID_INSN), size(size) {}

template <class A>
Disassembler<A>::Instruction::Instruction(cs_insn *raw)
    : address((PtrT)raw->address), id(raw->id), size((uint8_t)raw->size),
      opStr(raw->op_str) {}

template <class A>
Disassembler<A>::Disassembler(Macho::Context<false, P> *mCtx,
                              ActivityLogger *activity,
                              std::shared_ptr<spdlog::logger> logger)
    : activity(activity), logger(logger) {
  // Get data about text
  if (auto [seg, sect] = mCtx->getSection("__TEXT", "__text"); sect) {
    textData = mCtx->convertAddrP(sect->addr);
    textAddr = sect->addr;
    textSize = sect->size;
    imageAddr = seg->command->vmaddr;
  } else {
    return;
  }

  // get data in code entries
  if (auto dicCmd =
          mCtx->getLoadCommand<false, Macho::Loader::linkedit_data_command>(
              {LC_DATA_IN_CODE})) {
    if (dicCmd->datasize) {
      auto linkeditFile =
          mCtx->convertAddr(mCtx->getSegment("__LINKEDIT")->command->vmaddr)
              .second;
      diceStart = (data_in_code_entry *)(linkeditFile + dicCmd->dataoff);
      diceEnd = diceStart + (dicCmd->datasize / sizeof(data_in_code_entry));
    }
  }

  // Create Capstone engine
  cs_err err;
  if constexpr (std::is_same_v<A, Utils::Arch::x86_64>) {
    throw std::logic_error("Not implemented");
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle);
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                       std::is_same_v<A, Utils::Arch::arm64_32>) {
    err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
  } else {
    assert(!"Unreachable");
  }

  if (err != CS_ERR_OK) {
    throw std::runtime_error("Unable to open Capstone engine");
    return;
  }
}

template <class A> Disassembler<A>::~Disassembler() { cs_close(&handle); }

template <class A>
Disassembler<A>::Disassembler(Disassembler<A> &&o)
    : instructions(std::move(o.instructions)), activity(o.activity),
      logger(std::move(o.logger)), textData(o.textData), textAddr(o.textAddr),
      textSize(o.textSize), handle(o.handle) {
  o.activity = nullptr;
  o.textData = nullptr;
  o.textAddr = 0;
  o.textSize = 0;
  o.handle = 0;
}

template <class A>
Disassembler<A> &Disassembler<A>::operator=(Disassembler<A> &&o) {
  instructions = std::move(o.instructions);
  activity = o.activity;
  logger = std::move(o.logger);
  textData = o.textData;
  textAddr = o.textAddr;
  textSize = o.textSize;
  handle = o.handle;

  o.activity = nullptr;
  o.textData = nullptr;
  o.textAddr = 0;
  o.textSize = 0;
  o.handle = 0;
  return *this;
}

template <class A> void Disassembler<A>::disasm() {
  if (disassembled) {
    return;
  }

  activity->update("Disassembler", "disassembling (will appear frozen)");
  if (!textData) {
    return;
  }

  // Disassemble
  uint32_t currentOffset = 0;
  data_in_code_entry *nextDice = diceStart;
  while (currentOffset < textSize) {
    // Get the next stop offset
    uint32_t nextStop;
    if (nextDice < diceEnd) {
      nextStop = (uint32_t)(imageAddr + (PtrT)nextDice->offset - textAddr);
    } else {
      nextStop = (uint32_t)textSize;
    }

    while (true) {
      currentOffset = disasmNextChunk(currentOffset, nextStop);

      if (currentOffset < nextStop) {
        // need recovery
        currentOffset = recover(currentOffset);
      } else {
        break;
      }
    }

    // skip pass the dic
    if (nextDice < diceEnd) {
      currentOffset += nextDice->length;
      Utils::align(&currentOffset, 2);
    }
    nextDice++;
  }

  disassembled = true;
}

template <class A>
uint32_t Disassembler<A>::disasmNextChunk(uint32_t startOffset,
                                          uint32_t endOffset) {
  const auto data = textData + startOffset;
  const auto chunkSize = endOffset - startOffset;

  cs_insn *rawI;
  const auto count =
      cs_disasm(handle, data, chunkSize, textAddr + startOffset, 0, &rawI);
  if (count == 0) {
    return startOffset;
  }

  for (int i = 0; i < count; i++) {
    auto insn = rawI + i;
    instructions.emplace_back(insn);
  }

  auto lastI = rawI + count - 1;
  auto newOffset = (uint32_t)(lastI->address + lastI->size - textAddr);
  cs_free(rawI, count);
  return newOffset;
}

template <class A> uint32_t Disassembler<A>::recover(uint32_t offset) {
  if constexpr (std::is_same_v<A, Utils::Arch::x86_64>) {
    throw std::logic_error("Not implemented");
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    return recoverArm(offset);
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                       std::is_same_v<A, Utils::Arch::arm64_32>) {
    return recoverArm64(offset);
  } else {
    assert(!"Unreachable");
  }
}

template <class A> uint32_t Disassembler<A>::recoverArm(uint32_t offset) {
  auto data = textData + offset;
  uint16_t thumb1 = *(uint16_t *)data;
  uint16_t thumb2 = *((uint16_t *)data + 1);
  uint32_t arm = (thumb1 << 16) | thumb2;

  // ignore VFP instructions
  if ((arm & 0x0F000E10) == 0x0E000A00) {
    instructions.emplace_back(textAddr + offset, 4);
    return offset + 4;
  }

  instructions.emplace_back(textAddr + offset, 2);
  return offset + 2;
}

template <class A> uint32_t Disassembler<A>::recoverArm64(uint32_t offset) {
  instructions.emplace_back(textAddr + offset, 4);
  return offset + 4;
}

template class Disassembler<Utils::Arch::x86_64>;
template class Disassembler<Utils::Arch::arm>;
template class Disassembler<Utils::Arch::arm64>;
template class Disassembler<Utils::Arch::arm64_32>;
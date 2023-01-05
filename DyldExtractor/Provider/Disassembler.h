#ifndef __PROVIDER_DISASSEMBLER__
#define __PROVIDER_DISASSEMBLER__

#include "ActivityLogger.h"
#include "FunctionTracker.h"
#include <Macho/Context.h>
#include <capstone/capstone.h>
#include <set>
#include <spdlog/spdlog.h>

#define DISASM_INVALID_INSN 0

namespace DyldExtractor::Provider {

template <class A> class Disassembler {
  using P = A::P;
  using PtrT = P::PtrT;

public:
  struct Instruction {
    PtrT address;
    unsigned int id;
    uint8_t size;

    std::string opStr;

    /// @brief Create an invalid instruction
    Instruction(PtrT addr, uint8_t size);
    Instruction(cs_insn *raw);
  };

  using InstructionCacheT = std::vector<Instruction>;
  using ConstInstructionIt = InstructionCacheT::const_iterator;

  Disassembler(const Macho::Context<false, P> &mCtx,
               Provider::ActivityLogger &activity,
               std::shared_ptr<spdlog::logger> logger,
               Provider::FunctionTracker<P> &funcTracker);
  ~Disassembler();
  Disassembler(const Disassembler &) = delete;
  Disassembler(Disassembler &&o);
  Disassembler &operator=(const Disassembler &) = delete;
  Disassembler &operator=(Disassembler &&o);

  void load();
  ConstInstructionIt instructionAtAddr(PtrT addr) const;
  ConstInstructionIt instructionsBegin() const;
  ConstInstructionIt instructionsEnd() const;

private:
  /// @brief Disassemble an entire function
  /// @param offset Byte offset from the text seg
  /// @param size Size of function
  void disasmFunc(uint32_t offset, uint32_t size);

  /// @brief Disassemble part of a function
  /// @param offset Byte offset from the text seg
  /// @param size Size of chunk
  void disasmChunk(uint32_t offset, uint32_t size);

  /// @brief Recover from failed disassembly
  /// @return The size of the recovered instruction
  uint32_t recover(uint32_t offset);

  const Macho::Context<false, P> *mCtx;
  Provider::ActivityLogger *activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::FunctionTracker<P> *funcTracker;

  InstructionCacheT instructions;
  uint8_t *textData = nullptr; // text segment data
  PtrT textAddr = 0;           // text segment address
  bool disassembled = false;
  csh handle;

  static inline auto dataInCodeComp = [](const auto &rhs, const auto &lhs) {
    return rhs.offset < lhs.offset;
  };
  std::set<data_in_code_entry, decltype(dataInCodeComp)> dataInCodeEntries;
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_DISASSEMBLER__
#ifndef __PROVIDER_DISASSEMBLER__
#define __PROVIDER_DISASSEMBLER__

#include <Logger/ActivityLogger.h>
#include <Macho/Context.h>
#include <capstone/capstone.h>
#include <set>
#include <spdlog/spdlog.h>

namespace Provider {

template <class A> class Disassembler {
  using P = A::P;
  using PtrT = P::PtrT;

public:
  struct Instruction {
    PtrT address;
    unsigned int id;
    uint8_t size;

    std::string opStr;

    /// Create an invalid instruction
    Instruction(PtrT addr, uint8_t size);
    Instruction(cs_insn *raw);
  };

  Disassembler(Macho::Context<false, P> *mCtx, ActivityLogger *activity,
               std::shared_ptr<spdlog::logger> logger);
  ~Disassembler();
  Disassembler(const Disassembler &o) = delete;
  Disassembler(Disassembler &&o);
  Disassembler &operator=(const Disassembler &o) = delete;
  Disassembler &operator=(Disassembler &&o);

  void disasm();

  std::vector<Instruction> instructions;

private:
  uint32_t disasmNextChunk(uint32_t startOffset, uint32_t endOffset);
  uint32_t recover(uint32_t offset);
  uint32_t recoverArm(uint32_t offset);
  uint32_t recoverArm64(uint32_t offset);

  ActivityLogger *activity;
  std::shared_ptr<spdlog::logger> logger;

  uint8_t *textData = nullptr;
  PtrT textAddr = 0;
  PtrT textSize = 0;
  PtrT imageAddr = 0;
  bool disassembled = false;

  data_in_code_entry *diceStart = nullptr;
  data_in_code_entry *diceEnd = nullptr;

  csh handle;
};

} // namespace Provider

#endif // __PROVIDER_DISASSEMBLER__
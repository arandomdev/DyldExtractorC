#ifndef __CONVERTER_LINKEDIT_ENCODER_BINDINGV1__
#define __CONVERTER_LINKEDIT_ENCODER_BINDINGV1__

#include <Macho/Context.h>

namespace DyldExtractor::Converter::Linkedit::Encoder {

struct BindingV1Info {
  BindingV1Info(uint8_t _type, uint8_t _flags, uint16_t _threadedBindOrdinal,
                int _libraryOrdinal, const char *_symbolName, uint64_t
                _address, int64_t _addend);
  BindingV1Info(uint8_t t, int ord, const char *sym, bool weak_import,
                uint64_t addr, int64_t add);
  BindingV1Info(uint8_t t, const char *sym, bool non_weak_definition,
                uint64_t addr, int64_t add);

  uint8_t _type;
  uint8_t _flags;
  uint16_t _threadedBindOrdinal;
  int _libraryOrdinal;
  const char *_symbolName;
  uint64_t _address;
  int64_t _addend;

  // for sorting
  int operator<(const BindingV1Info &rhs) const;
};

template <class P>
std::vector<uint8_t> encodeBindingV1(std::vector<BindingV1Info> &info,
                                     const Macho::Context<false, P> &mCtx);

} // namespace DyldExtractor::Converter::Linkedit::Encoder

#endif // __CONVERTER_LINKEDIT_ENCODER_BINDINGV1__
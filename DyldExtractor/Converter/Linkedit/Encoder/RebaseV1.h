#ifndef __CONVERTER_LINKEDIT_ENCODER_REBASEV1__
#define __CONVERTER_LINKEDIT_ENCODER_REBASEV1__

#include <Macho/Context.h>

namespace DyldExtractor::Converter::Linkedit::Encoder {

struct RebaseV1Info {
  RebaseV1Info(uint8_t t, uint64_t addr);
  uint8_t _type;
  uint64_t _address;
};

template <class P>
std::vector<uint8_t> encodeRebaseV1(const std::vector<RebaseV1Info> &info,
                                    const Macho::Context<false, P> &mCtx);

} // namespace DyldExtractor::Converter::Linkedit::Encoder

#endif // __CONVERTER_LINKEDIT_ENCODER_REBASEV1__
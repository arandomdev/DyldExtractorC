#ifndef __CONVERTER_REBASE_REBASEV1__
#define __CONVERTER_REBASE_REBASEV1__

#include <Macho/Context.h>
#include <stdint.h>
#include <vector>

namespace Converter {

struct RebaseV1Info {
  uint8_t type;
  uint64_t address;
};

template <class P>
std::vector<uint8_t> generateRebaseV1(const std::vector<RebaseV1Info> &info,
                                      const Macho::Context<false, P> &mCtx);

} // namespace Converter

#endif // __CONVERTER_REBASE_REBASEV1__
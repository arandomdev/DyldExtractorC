#include "MetadataGenerator.h"

#include "Encoder/Encoder.h"
#include <Converter/Objc/Objc.h>
#include <Macho/Context.h>

using namespace DyldExtractor;
using namespace Converter;
using namespace Linkedit;

template <class A>
void Converter::generateMetadata(Utils::ExtractionContext<A> &eCtx) {
  using P = A::P;

  eCtx.activity->update("Metadata Generator", "Starting Up");
  auto dyldInfo = eCtx.mCtx->getFirstLC<Macho::Loader::dyld_info_command>();

  // Check if new-style encoding can be used
  if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
    if (!dyldInfo) {
      Encoder::ChainedEncoder(eCtx).generateMetadata();
      eCtx.activity->update(std::nullopt, "Done");
      return;
    }
  }

  Encoder::generateLegacyMetadata(eCtx);
  eCtx.activity->update(std::nullopt, "Done");
}

#define X(T)                                                                   \
  template void Converter::generateMetadata<T>(Utils::ExtractionContext<T> &   \
                                               eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X
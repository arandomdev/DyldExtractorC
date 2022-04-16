#include "Slide.h"

#include <Utils/Architectures.h>

using namespace Converter;

struct mappingSlideInfo {
    //
};

template <class P>
void Converter::processSlideInfo(Utils::ExtractionContext<P> eCtx) {
    //
}

template <>
void Converter::processSlideInfo<Utils::Pointer32>(
    Utils::ExtractionContext<Utils::Pointer32> eCtx);
template <>
void Converter::processSlideInfo<Utils::Pointer64>(
    Utils::ExtractionContext<Utils::Pointer64> eCtx);
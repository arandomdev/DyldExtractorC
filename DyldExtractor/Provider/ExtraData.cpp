#include "ExtraData.h"

using namespace Provider;

template <class P>
ExtraData<P>::ExtraData(ExtraData<P>::PtrT addr) : baseAddr(addr) {}

template class ExtraData<Utils::Pointer32>;
template class ExtraData<Utils::Pointer64>;

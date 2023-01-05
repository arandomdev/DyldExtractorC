#include "ExtraData.h"

using namespace DyldExtractor;
using namespace Provider;

template <class P>
ExtraData<P>::ExtraData(std::string extendsSeg, ExtraData<P>::PtrT addr,
                        PtrT size)
    : extendsSeg(extendsSeg), baseAddr(addr), store(size) {}

template <class P> ExtraData<P>::PtrT ExtraData<P>::getBaseAddr() const {
  return baseAddr;
}

template <class P> ExtraData<P>::PtrT ExtraData<P>::getEndAddr() const {
  return baseAddr + (PtrT)store.size();
}

template <class P> uint8_t *ExtraData<P>::getData() { return store.data(); }
template <class P> const uint8_t *ExtraData<P>::getData() const {
  return store.data();
}

template <class P> const std::string &ExtraData<P>::getExtendsSeg() const {
  return extendsSeg;
}

template class ExtraData<Utils::Arch::Pointer32>;
template class ExtraData<Utils::Arch::Pointer64>;

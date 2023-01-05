#ifndef __PROVIDER_EXTRADATA__
#define __PROVIDER_EXTRADATA__

#include <Macho/Loader.h>
#include <Utils/Architectures.h>
#include <string>
#include <vector>

namespace DyldExtractor::Provider {

/// @brief Contains in memory data that is added to the image. Extends a
///   segment.
template <class P> class ExtraData {
  using PtrT = P::PtrT;

public:
  ExtraData(std::string extendsSeg, PtrT addr, PtrT size);
  ExtraData(const ExtraData &) = delete;
  ExtraData(ExtraData &&) = default;
  ExtraData &operator=(const ExtraData &) = delete;
  ExtraData &operator=(ExtraData &&) = default;

  /// @brief Get the beginning address.
  PtrT getBaseAddr() const;

  /// @brief Get the end address.
  PtrT getEndAddr() const;

  uint8_t *getData();
  const uint8_t *getData() const;

  /// @brief Get the name of the segment that this extends.
  const std::string &getExtendsSeg() const;

private:
  std::string extendsSeg;
  PtrT baseAddr;
  std::vector<uint8_t> store;
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_EXTRADATA__
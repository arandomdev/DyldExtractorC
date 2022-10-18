#ifndef __PROVIDER_EXTRADATA__
#define __PROVIDER_EXTRADATA__

#include <Utils/Architectures.h>
#include <stdint.h>
#include <vector>

namespace DyldExtractor::Provider {

template <class P> class ExtraData {
  using PtrT = P::PtrT;

public:
  ExtraData() = default;
  ExtraData(PtrT addr);
  ExtraData(const ExtraData &) = delete;
  ExtraData(ExtraData &&) = default;
  ExtraData &operator=(const ExtraData &) = delete;
  ExtraData &operator=(ExtraData &&) = default;

  /// @brief Add data, invalidates all pointers
  /// @tparam T The type of data
  /// @param newData The data
  /// @return The address of the new data
  template <class T> PtrT add(T newData) {
    PtrT dataAddr = baseAddr + (PtrT)store.size();
    auto source = reinterpret_cast<uint8_t *>(&newData);
    store.insert(store.end(), source, source + sizeof(T));

    if (auto aligned = Utils::align(sizeof(T), sizeof(PtrT));
        aligned != sizeof(T)) {
      store.insert(store.end(), aligned - sizeof(T), 0x00);
    }

    return dataAddr;
  }

  /// @brief Get a pointer to data.
  /// @tparam T The type of data.
  /// @param addr The address of the data
  /// @return A pointer to the data.
  template <class T> T *get(PtrT addr) {
    return reinterpret_cast<T *>(store.size() + (addr - baseAddr));
  }

private:
  PtrT baseAddr;
  std::vector<uint8_t> store;
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_EXTRADATA__
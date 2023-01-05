#ifndef __PROVIDER_BINDINFO__
#define __PROVIDER_BINDINFO__

#include "ActivityLogger.h"
#include <Macho/Context.h>
#include <map>

namespace DyldExtractor::Provider {

struct BindRecord {
  uint64_t address = 0;
  uint8_t type = 0;
  uint8_t flags = 0;
  int libOrdinal = 0;
  char *symbolName = nullptr;
  int64_t addend = 0;
};

template <class P> class BindInfo {
public:
  BindInfo(const Macho::Context<false, P> &mCtx,
           Provider::ActivityLogger &activity);
  BindInfo(const BindInfo &) = delete;
  BindInfo &operator=(const BindInfo &) = delete;

  /// @brief Read and load all binds
  void load();

  /// @brief Get all regular bind records.
  const std::vector<BindRecord> &getBinds() const;

  /// @brief Get all weak bind records.
  const std::vector<BindRecord> &getWeakBinds() const;

  /// @brief Get all lazy bind records.
  const std::map<uint32_t, BindRecord> &getLazyBinds() const;

  /// @brief Get a lazy bind record.
  /// @param offset The offset to the bind record.
  /// @return The bind record.
  const BindRecord *getLazyBind(uint32_t offset) const;

  bool hasLazyBinds() const;

private:
  const Macho::Context<false, P> *mCtx;
  Provider::ActivityLogger *activity;

  std::vector<BindRecord> binds;
  std::vector<BindRecord> weakBinds;
  std::map<uint32_t, BindRecord> lazyBinds;
  bool _hasLazyBinds;

  bool dataLoaded = false;
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_BINDINFO__
#ifndef __PROVIDER_BINDINFO__
#define __PROVIDER_BINDINFO__

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
  BindInfo(const Macho::Context<false, P> &mCtx);
  BindInfo(const BindInfo &) = delete;
  BindInfo &operator=(const BindInfo &) = delete;

  /// @brief Get all regular bind records.
  const std::vector<BindRecord> &getBinds();

  /// @brief Get all weak bind records.
  const std::vector<BindRecord> &getWeakBinds();

  /// @brief Get all lazy bind records.
  const std::map<uint32_t, BindRecord> &getLazyBinds();

  /// @brief Get a lazy bind record.
  /// @param offset The offset to the bind record.
  /// @return The bind record.
  const BindRecord *getLazyBind(uint32_t offset);

  bool hasLazyBinds() const;

private:
  void readBinds();
  void readWeakBinds();
  void readLazyBinds();

  const Macho::Context<false, P> *mCtx;
  const uint8_t *linkeditFile;
  const dyld_info_command *dyldInfo;

  std::vector<BindRecord> binds;
  std::vector<BindRecord> weakBinds;
  std::map<uint32_t, BindRecord> lazyBinds;

  struct {
    bool bind = false;
    bool weak = false;
    bool lazy = false;
  } readStatus;
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_BINDINFO__
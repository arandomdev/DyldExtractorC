#ifndef __PROVIDER_FUNCTIONTRACKER__
#define __PROVIDER_FUNCTIONTRACKER__

#include <MachO/Context.h>
#include <spdlog/spdlog.h>

namespace DyldExtractor::Provider {

/// @brief Reads and stores function starts.
template <class P> class FunctionTracker {
  using PtrT = P::PtrT;

public:
  class Function {
  public:
    PtrT address;
    PtrT size;
  };

  FunctionTracker(const Macho::Context<false, P> &mCtx,
                  std::shared_ptr<spdlog::logger> logger);
  FunctionTracker(const FunctionTracker &) = delete;
  FunctionTracker(FunctionTracker &&o) = default;
  FunctionTracker &operator=(const FunctionTracker &) = delete;
  FunctionTracker &operator=(FunctionTracker &&o) = default;

  void load();
  const std::vector<Function> &getFunctions() const;

private:
  const Macho::Context<false, P> *mCtx;
  std::shared_ptr<spdlog::logger> logger;

  bool loaded = false;
  std::vector<Function> functions;
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_FUNCTIONTRACKER__
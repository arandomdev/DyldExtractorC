#ifndef __CONVERTER_STUBS_SYMBOLPOINTERCACHE__
#define __CONVERTER_STUBS_SYMBOLPOINTERCACHE__

#include <Provider/BindInfo.h>
#include <Provider/Symbolizer.h>

namespace DyldExtractor::Converter::Stubs {

template <class A> class Fixer;

template <class A> class SymbolPointerCache {
  using P = A::P;
  using PtrT = P::PtrT;

public:
  enum class PointerType {
    normal, // Commonly in __got
    lazy,   // Commonly in __la_symbol_ptr
    auth    // Commonly in __auth_got
  };

  SymbolPointerCache(Fixer<A> &delegate);
  PointerType getPointerType(const auto sect) const;
  void scanPointers();

  /// @brief Check if a pointer is free to use
  bool isAvailable(PointerType pType, PtrT addr);
  /// @brief Provide symbolic info for a unnamed pointer
  void namePointer(PointerType pType, PtrT addr,
                   const Provider::SymbolicInfo &info);
  const Provider::SymbolicInfo *getPointerInfo(PointerType pType,
                                               PtrT addr) const;

  /// TODO: Add weak type
  using PtrMapT = std::map<PtrT, std::shared_ptr<Provider::SymbolicInfo>>;
  struct {
    PtrMapT normal;
    PtrMapT lazy;
    PtrMapT auth;
  } ptr;

  using ReverseMapT = std::map<std::reference_wrapper<const std::string>,
                               std::set<PtrT>, std::less<const std::string>>;
  struct {
    ReverseMapT normal;
    ReverseMapT lazy;
    ReverseMapT auth;
  } reverse;

  struct {
    std::set<PtrT> normal;
    std::set<PtrT> lazy;
    std::set<PtrT> auth;
  } unnamed;

  struct {
    std::set<PtrT> normal;
    std::set<PtrT> lazy;
    std::set<PtrT> auth;
  } used;

private:
  std::map<PtrT, Provider::BindRecord> getBindRecords();
  void addPointerInfo(PointerType pType, PtrT pAddr,
                      const Provider::SymbolicInfo &info);

  Fixer<A> &delegate;
  Macho::Context<false, P> &mCtx;
  Logger::Activity &activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::BindInfo<P> &bindInfo;
};

} // namespace DyldExtractor::Converter::Stubs

#endif // __CONVERTER_STUBS_SYMBOLPOINTERCACHE__
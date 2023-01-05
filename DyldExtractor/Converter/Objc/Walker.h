#ifndef __CONVERTER_OBJC_WALKER__
#define __CONVERTER_OBJC_WALKER__

#include "Atoms.h"
#include <Objc/Abstraction.h>
#include <Utils/ExtractionContext.h>
#include <optional>

namespace DyldExtractor::Converter::ObjcFixer {
template <class A> class Placer;

template <class A> class Walker {
  using P = A::P;
  using PtrT = P::PtrT;

  // allow placer to access atoms
  friend class Placer<A>;

public:
  Walker(Utils::ExtractionContext<A> &eCtx);
  bool walkAll();

private:
  bool parseOptInfo();

  ClassAtom<A> *walkClass(const PtrT addr);
  ClassDataAtom<A> *walkClassData(const PtrT addr);
  IvarLayoutAtom<P> *walkIvarLayout(const PtrT addr);
  StringAtom<P> *walkString(const PtrT addr);
  MethodListAtom<P> *walkMethodList(const PtrT addr);
  SmallMethodListAtom<P> *walkSmallMethodList(const PtrT addr,
                                              Objc::method_list_t data);
  LargeMethodListAtom<P> *walkLargeMethodList(const PtrT addr,
                                              Objc::method_list_t data);
  ProtocolListAtom<A> *walkProtocolList(const PtrT addr);
  ProtocolAtom<A> *walkProtocol(const PtrT addr);
  PropertyListAtom<P> *walkPropertyList(const PtrT addr);
  ExtendedMethodTypesAtom<P> *walkExtendedMethodTypes(const PtrT addr,
                                                      const uint32_t count);
  IvarListAtom<A> *walkIvarList(const PtrT addr);
  IvarOffsetAtom<A> *walkIvarOffset(const PtrT addr);
  CategoryAtom<A> *walkCategory(const PtrT addr);
  ImpAtom<P> *walkImp(const PtrT addr);

  PointerAtom<P, StringAtom<P>> *makeSmallMethodSelRef(const PtrT stringAddr);

  /// @brief Find the list in a relative_list_list_t with the same image index.
  /// @param addr VM address of the relative_list_list_t
  /// @return Address of the list
  std::optional<PtrT> findInImageRelList(const PtrT addr) const;

  const Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  Provider::ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;

  Provider::BindInfo<P> &bindInfo;
  Provider::PointerTracker<P> &ptrTracker;
  Provider::Symbolizer<A> &symbolizer;

  uint16_t imageIndex;
  bool hasCategoryClassProperties = false;
  std::optional<PtrT> relMethodSelBaseAddr;

  /// @brief Cache of atoms, keys are the original addresses
  template <class T> using CacheT = std::map<PtrT, T>;
  struct {
    CacheT<ClassAtom<A>> classes;
    CacheT<ClassDataAtom<A>> classData;
    CacheT<IvarLayoutAtom<P>> ivarLayouts;
    CacheT<StringAtom<P>> strings;
    CacheT<SmallMethodListAtom<P>> smallMethodLists;
    CacheT<LargeMethodListAtom<P>> largeMethodLists;
    CacheT<ProtocolListAtom<A>> protocolLists;
    CacheT<ProtocolAtom<A>> protocols;
    CacheT<PropertyListAtom<P>> propertyLists;
    CacheT<ExtendedMethodTypesAtom<P>> extendedMethodTypes;
    CacheT<IvarListAtom<A>> ivarLists;
    CacheT<IvarOffsetAtom<A>> ivarOffsets;
    CacheT<CategoryAtom<A>> categories;
    CacheT<ImpAtom<P>> imps;

    // Key is the same as the string
    CacheT<PointerAtom<P, StringAtom<P>>> smallMethodSelRefs;
  } atoms;

  /// @brief Cache of pointers that need to be fixed after placing atoms
  struct {
    CacheT<PointerAtom<P, ClassAtom<A>>> classes;
    CacheT<PointerAtom<P, CategoryAtom<A>>> categories;
    CacheT<PointerAtom<P, ProtocolAtom<A>>> protocols;
    CacheT<PointerAtom<P, StringAtom<P>>> selectorRefs;
    CacheT<PointerAtom<P, ProtocolAtom<A>>> protocolRefs;
    CacheT<BindPointerAtom<P, ClassAtom<A>>> classRefs;
    CacheT<BindPointerAtom<P, ClassAtom<A>>> superRefs;
  } pointers;
};

} // namespace DyldExtractor::Converter::ObjcFixer

#endif // __CONVERTER_OBJC_WALKER__
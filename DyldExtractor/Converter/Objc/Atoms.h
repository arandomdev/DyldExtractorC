#ifndef __CONVERTER_OBJC_ATOMS__
#define __CONVERTER_OBJC_ATOMS__

#include <Objc/Abstraction.h>
#include <Provider/Symbolizer.h>
#include <Utils/Utils.h>
#include <list>
#include <optional>

namespace DyldExtractor::Converter::ObjcFixer {

template <class A> class ClassAtom;
template <class A> class ProtocolListAtom;

#pragma region MetaAtoms
/// @brief Base atom type
template <class P> class AtomBase {
  using PtrT = P::PtrT;

public:
  /// @brief Get all child atoms.
  /// @return A vector of pairs of the atom pointers and their relative offsets
  virtual std::vector<std::pair<AtomBase<P> *, PtrT>> getAtoms() const {
    return std::vector<std::pair<AtomBase<P> *, PtrT>>();
  }

  /// @brief Gets the encoded size of the entire atom, including children
  virtual PtrT encodedSize() const { return 0; }

  /// @brief Propagate any relationships to the data structure
  /// @details Must be called after finalAddr for dependencies are set.
  virtual void propagate() {
    for (auto &[atom, offset] : getAtoms()) {
      atom->propagate();
    }
  }

  /// @brief Gets the finalAddr, must be set first
  PtrT finalAddr() const { return _finalAddr.value(); }

  /// @brief Sets the final address for the atom and children.
  void setFinalAddr(PtrT addr) {
    assert(!_finalAddr && "Final address was already set.");
    _finalAddr = addr;

    for (auto &[atom, offset] : getAtoms()) {
      atom->setFinalAddr(addr + offset);
    }
  }

  /// @brief If the final placement is in the image
  bool placedInImage = false;

private:
  std::optional<PtrT> _finalAddr;
};

/// @brief Generic atom
/// @tparam T The type of the encoded data
template <class P, class T> class Atom : public AtomBase<P> {
protected:
  using PtrT = P::PtrT;
  using DataT = T;

public:
  // All atoms must be created and accessed inplace
  Atom(const Atom &) = delete;
  Atom(Atom &&) = delete;
  Atom &operator=(const Atom &) = delete;
  Atom &operator=(Atom &&) = delete;

  Atom(T data) : data(data) {}

  virtual PtrT encodedSize() const override { return sizeof(T); }

  T data;
};
#pragma endregion MetaAtoms

#pragma region RelationalAtoms
/// @brief Represents a generic relationship to an atom, should not be used
/// @tparam AtomT The relationship atom type
/// @tparam DataT The data type to encode the relationship
template <class P, class AtomT, class DataT>
class ReferenceAtom : public Atom<P, DataT> {
public:
  using Atom<P, DataT>::Atom;
  AtomT *ref = nullptr;
};

/// @brief Represents a relational pointer to an atom that's part of a struct
/// @tparam AtomT The relationship atom type
template <class P, class AtomT>
class FieldRefAtom final : public ReferenceAtom<P, AtomT, typename P::PtrT *> {
  using PtrT = P::PtrT;

public:
  using ReferenceAtom<P, AtomT, PtrT *>::ReferenceAtom;
  virtual void propagate() override {
    ReferenceAtom<P, AtomT, PtrT *>::propagate();
    *this->data = this->ref ? this->ref->finalAddr() : 0;
  }
};

/// @brief Represents a relation pointer to an atom, or an optional bind, that's
///   part of a struct
/// @tparam AtomT The relational atom type
template <class P, class AtomT>
class BindRefAtom final : public ReferenceAtom<P, AtomT, typename P::PtrT *> {
  using PtrT = P::PtrT;

public:
  using ReferenceAtom<P, AtomT, PtrT *>::ReferenceAtom;
  BindRefAtom(std::shared_ptr<Provider::SymbolicInfo> bind) : bind(bind) {}

  virtual void propagate() override {
    ReferenceAtom<P, AtomT, PtrT *>::propagate();

    if (bind) {
      *this->data = 0;
    } else if (this->ref) {
      *this->data = this->ref->finalAddr();
    } else {
      *this->data = 0;
    }
  }

  std::shared_ptr<Provider::SymbolicInfo> bind; // optional bind, takes priority
};

/// @brief Represents an atom relationship based on an offset, that's part of a
///   struct
/// @tparam AtomT The relational atom type
template <class P, class AtomT>
class RelativeRefAtom final : public ReferenceAtom<P, AtomT, int32_t *> {
public:
  using ReferenceAtom<P, AtomT, int32_t *>::ReferenceAtom;
  virtual void propagate() override {
    ReferenceAtom<P, AtomT, int32_t *>::propagate();

    if (this->ref) {
      typename P::SPtrT offset = this->ref->finalAddr() - this->finalAddr();
      assert(offset > 0 ? offset <= INT32_MAX : offset >= INT32_MIN);
      *this->data = (int32_t)offset;
    } else {
      *this->data = 0;
    }
  }
};

/// @brief Represents a pointer.
/// @tparam AtomT The relational atom type
template <class P, class AtomT>
class PointerAtom final : public ReferenceAtom<P, AtomT, typename P::PtrT> {
  using PtrT = P::PtrT;

public:
  using ReferenceAtom<P, AtomT, PtrT>::ReferenceAtom;
  PointerAtom() : ReferenceAtom<P, AtomT, PtrT>(0) {}
  virtual void propagate() override {
    ReferenceAtom<P, AtomT, PtrT>::propagate();
    this->data = this->ref ? this->ref->finalAddr() : 0;
  }
};

/// @brief Represents a pointer that could be a bind
/// @tparam AtomT The relational atom type
template <class P, class AtomT>
class BindPointerAtom final : public ReferenceAtom<P, AtomT, typename P::PtrT> {
  using PtrT = P::PtrT;

public:
  ReferenceAtom<P, AtomT, PtrT>::ReferenceAtom;
  BindPointerAtom() : ReferenceAtom<P, AtomT, PtrT>(0) {}

  virtual void propagate() override {
    ReferenceAtom<P, AtomT, PtrT>::propagate();

    if (bind) {
      this->data = 0;
    } else if (this->ref) {
      this->data = this->ref->finalAddr();
    } else {
      this->data = 0;
    }
  }

  std::shared_ptr<Provider::SymbolicInfo> bind; // optional bind, takes priority
};
#pragma endregion RelationalAtoms

#pragma region BasicAtoms
template <class A>
using IvarOffsetType =
    std::conditional_t<std::is_same_v<A, Utils::Arch::x86_64>, uint64_t,
                       uint32_t>;

/// @brief Represents an integer constant. uint64_t for x86_64
template <class A>
class IvarOffsetAtom final : public Atom<typename A::P, IvarOffsetType<A>> {
public:
  using Atom<typename A::P, IvarOffsetType<A>>::Atom;
};

/// @brief Represents a null terminated string
template <class P> class StringAtom final : public Atom<P, const char *> {
  using PtrT = P::PtrT;

public:
  using Atom<P, const char *>::Atom;
  virtual PtrT encodedSize() const override {
    return (PtrT)strlen(this->data) + 1; // include null terminator
  }
};

/// @brief Represents a null terminated bitmap
template <class P>
class IvarLayoutAtom final : public Atom<P, const uint8_t *> {
  using PtrT = P::PtrT;

public:
  using Atom<P, const uint8_t *>::Atom;
  virtual PtrT encodedSize() const override {
    const uint8_t *end = this->data;
    for (; *end != '\0'; ++end)
      ;
    return (PtrT)(end - this->data + 1); // include null terminator
  }
};

/// @brief Represents a function implementation
template <class P> class ImpAtom final : public Atom<P, const uint8_t *> {
public:
  using Atom<P, const uint8_t *>::Atom;
};
#pragma endregion BasicAtoms

#pragma region StructureAtoms
/// @brief Represents a small method in a method_list_t
template <class P>
class SmallMethodAtom final : public Atom<P, Objc::method_small_t> {
  using PtrT = P::PtrT;
  using DataT = Objc::method_small_t;

public:
  SmallMethodAtom(DataT data)
      : Atom<P, DataT>(data), name(&this->data.name), types(&this->data.types),
        imp(&this->data.imp) {}

  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    return {{(AtomBase<P> *)&name, (PtrT)offsetof(DataT, name)},
            {(AtomBase<P> *)&types, (PtrT)offsetof(DataT, types)},
            {(AtomBase<P> *)&imp, (PtrT)offsetof(DataT, imp)}};
  }

  RelativeRefAtom<P, PointerAtom<P, StringAtom<P>>> name;
  RelativeRefAtom<P, StringAtom<P>> types;
  RelativeRefAtom<P, ImpAtom<P>> imp;
};

/// @brief Represents a Large method in a method_list_t
template <class P>
class LargeMethodAtom final : public Atom<P, Objc::method_large_t<P>> {
  using PtrT = P::PtrT;
  using DataT = Objc::method_large_t<P>;

public:
  LargeMethodAtom(DataT data)
      : Atom<P, DataT>(data), name(&this->data.name), types(&this->data.types),
        imp(&this->data.imp) {}

  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    return {{(AtomBase<P> *)&name, (PtrT)offsetof(DataT, name)},
            {(AtomBase<P> *)&types, (PtrT)offsetof(DataT, types)},
            {(AtomBase<P> *)&imp, (PtrT)offsetof(DataT, imp)}};
  }

  FieldRefAtom<P, StringAtom<P>> name;
  FieldRefAtom<P, StringAtom<P>> types;
  FieldRefAtom<P, ImpAtom<P>> imp;
};

/// @brief Represents a generic method_list_t
template <class P> class MethodListAtom : public Atom<P, Objc::method_list_t> {
protected:
  using DataT = Objc::method_list_t;

public:
  using Atom<P, DataT>::Atom;
};

/// @brief Represents a method_list_t with small methods
template <class P> class SmallMethodListAtom final : public MethodListAtom<P> {
  using PtrT = P::PtrT;
  using DataT = MethodListAtom<P>::DataT;

public:
  using MethodListAtom<P>::MethodListAtom;
  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    std::vector<std::pair<AtomBase<P> *, PtrT>> atoms;
    atoms.reserve(entries.size());

    PtrT offset = sizeof(DataT);
    for (auto &method : entries) {
      atoms.emplace_back((AtomBase<P> *)&method, offset);
      offset += this->data.getEntsize();
    }

    return atoms;
  }

  virtual PtrT encodedSize() const override {
    PtrT size =
        (PtrT)sizeof(DataT) + (this->data.getEntsize() * this->data.count);
    return Utils::align(size, sizeof(PtrT));
  }

  std::list<SmallMethodAtom<P>> entries;
};

/// @brief Represents a method_list_t with large methods
template <class P> class LargeMethodListAtom final : public MethodListAtom<P> {
  using PtrT = P::PtrT;
  using DataT = MethodListAtom<P>::DataT;

public:
  using MethodListAtom<P>::MethodListAtom;
  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    std::vector<std::pair<AtomBase<P> *, PtrT>> atoms;
    atoms.reserve(entries.size());

    PtrT offset = sizeof(DataT);
    for (auto &method : entries) {
      atoms.emplace_back((AtomBase<P> *)&method, offset);
      offset += this->data.getEntsize();
    }

    return atoms;
  }

  virtual PtrT encodedSize() const override {
    return (PtrT)sizeof(DataT) + (this->data.getEntsize() * this->data.count);
  }

  std::list<LargeMethodAtom<P>> entries;
};

template <class P>
class PropertyAtom final : public Atom<P, Objc::property_t<P>> {
  using PtrT = P::PtrT;
  using DataT = Objc::property_t<P>;

public:
  PropertyAtom(DataT data)
      : Atom<P, DataT>(data), name(&this->data.name),
        attributes(&this->data.attributes) {}

  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    return {{(AtomBase<P> *)&name, (PtrT)offsetof(DataT, name)},
            {(AtomBase<P> *)&attributes, (PtrT)offsetof(DataT, attributes)}};
  }

  FieldRefAtom<P, StringAtom<P>> name;
  FieldRefAtom<P, StringAtom<P>> attributes;
};

template <class P>
class PropertyListAtom final : public Atom<P, Objc::property_list_t> {
  using PtrT = P::PtrT;
  using DataT = Objc::property_list_t;

public:
  using Atom<P, DataT>::Atom;
  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    std::vector<std::pair<AtomBase<P> *, PtrT>> atoms;
    atoms.reserve(entries.size());

    PtrT offset = sizeof(DataT);
    for (auto &property : entries) {
      atoms.emplace_back((AtomBase<P> *)&property, offset);
      offset += this->data.entsize;
    }

    return atoms;
  }

  virtual PtrT encodedSize() const override {
    return this->data.entsize * this->data.count;
  }

  std::list<PropertyAtom<P>> entries;
};

template <class P>
class ExtendedMethodTypesAtom final : public Atom<P, typename P::PtrT> {
  using PtrT = P::PtrT;

public:
  ExtendedMethodTypesAtom() : Atom<P, typename P::PtrT>(0) {}

  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    std::vector<std::pair<AtomBase<P> *, PtrT>> atoms;
    atoms.reserve(entries.size());

    PtrT offset = 0;
    for (auto &type : entries) {
      atoms.emplace_back((AtomBase<P> *)&type, offset);
      offset += sizeof(PtrT);
    }

    return atoms;
  }

  virtual PtrT encodedSize() const override {
    return (PtrT)(sizeof(PtrT) * entries.size());
  }

  std::list<PointerAtom<P, StringAtom<P>>> entries;
};

/// @brief Represents a protocol_t
template <class A>
class ProtocolAtom final
    : public Atom<typename A::P, Objc::protocol_t<typename A::P>> {
  using P = A::P;
  using PtrT = P::PtrT;
  using DataT = Objc::protocol_t<P>;

public:
  ProtocolAtom(DataT data)
      : Atom<P, DataT>(data), isa(&this->data.isa), name(&this->data.name),
        protocols(&this->data.protocols),
        instanceMethods(&this->data.instanceMethods),
        classMethods(&this->data.classMethods),
        optionalInstanceMethods(&this->data.optionalInstanceMethods),
        optionalClassMethods(&this->data.optionalClassMethods),
        instanceProperties(&this->data.instanceProperties),
        extendedMethodTypes(&this->data.extendedMethodTypes),
        demangledName(&this->data.demangledName),
        classProperties(&this->data.classProperties) {}

  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    return {
        {(AtomBase<P> *)&isa, (PtrT)offsetof(DataT, isa)},
        {(AtomBase<P> *)&name, (PtrT)offsetof(DataT, name)},
        {(AtomBase<P> *)&protocols, (PtrT)offsetof(DataT, protocols)},
        {(AtomBase<P> *)&instanceMethods,
         (PtrT)offsetof(DataT, instanceMethods)},
        {(AtomBase<P> *)&classMethods, (PtrT)offsetof(DataT, classMethods)},
        {(AtomBase<P> *)&optionalInstanceMethods,
         (PtrT)offsetof(DataT, optionalInstanceMethods)},
        {(AtomBase<P> *)&optionalClassMethods,
         (PtrT)offsetof(DataT, optionalClassMethods)},
        {(AtomBase<P> *)&instanceProperties,
         (PtrT)offsetof(DataT, instanceProperties)},
        {(AtomBase<P> *)&extendedMethodTypes,
         (PtrT)offsetof(DataT, extendedMethodTypes)},
        {(AtomBase<P> *)&demangledName, (PtrT)offsetof(DataT, demangledName)},
        {(AtomBase<P> *)&classProperties,
         (PtrT)offsetof(DataT, classProperties)}};
  }

  virtual PtrT encodedSize() const override { return this->data.size; }

  BindRefAtom<P, ClassAtom<A>> isa;
  FieldRefAtom<P, StringAtom<P>> name;
  FieldRefAtom<P, ProtocolListAtom<A>> protocols;
  FieldRefAtom<P, MethodListAtom<P>> instanceMethods;
  FieldRefAtom<P, MethodListAtom<P>> classMethods;
  FieldRefAtom<P, MethodListAtom<P>> optionalInstanceMethods;
  FieldRefAtom<P, MethodListAtom<P>> optionalClassMethods;
  FieldRefAtom<P, PropertyListAtom<P>> instanceProperties;

  FieldRefAtom<P, ExtendedMethodTypesAtom<P>> extendedMethodTypes;
  FieldRefAtom<P, StringAtom<P>> demangledName;
  FieldRefAtom<P, PropertyListAtom<P>> classProperties;
};

/// @brief Represents a protocol_list_t
template <class A>
class ProtocolListAtom final
    : public Atom<typename A::P, Objc::protocol_list_t<typename A::P>> {
  using P = A::P;
  using PtrT = P::PtrT;
  using DataT = Objc::protocol_list_t<P>;

public:
  using Atom<P, DataT>::Atom;
  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    std::vector<std::pair<AtomBase<P> *, PtrT>> atoms;
    atoms.reserve(entries.size());

    PtrT offset = sizeof(DataT);
    for (auto &protocol : entries) {
      atoms.emplace_back((AtomBase<P> *)&protocol, offset);
      offset += sizeof(PtrT);
    }

    return atoms;
  }

  virtual PtrT encodedSize() const override {
    return (PtrT)(sizeof(DataT) +
                  (sizeof(Objc::protocol_t<P>) * entries.size()));
  }

  std::list<PointerAtom<P, ProtocolAtom<A>>> entries;
};

/// @brief Represents an ivar_t
template <class A>
class IvarAtom final : public Atom<typename A::P, Objc::ivar_t<typename A::P>> {
  using P = A::P;
  using PtrT = P::PtrT;
  using DataT = Objc::ivar_t<P>;

public:
  IvarAtom(DataT data)
      : Atom<P, DataT>(data), offset(&this->data.offset),
        name(&this->data.name), type(&this->data.type) {}

  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    return {{(AtomBase<P> *)&offset, (PtrT)offsetof(DataT, offset)},
            {(AtomBase<P> *)&name, (PtrT)offsetof(DataT, name)},
            {(AtomBase<P> *)&type, (PtrT)offsetof(DataT, type)}};
  }

  FieldRefAtom<P, IvarOffsetAtom<A>> offset;
  FieldRefAtom<P, StringAtom<P>> name;
  FieldRefAtom<P, StringAtom<P>> type;
};

/// @brief Represents an ivar_list_t
template <class A>
class IvarListAtom final : public Atom<typename A::P, Objc::ivar_list_t> {
  using P = A::P;
  using PtrT = P::PtrT;
  using DataT = Objc::ivar_list_t;

public:
  using Atom<P, DataT>::Atom;
  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    std::vector<std::pair<AtomBase<P> *, PtrT>> atoms;
    atoms.reserve(entries.size());

    PtrT offset = sizeof(DataT);
    for (auto &ivar : entries) {
      atoms.emplace_back((AtomBase<P> *)&ivar, offset);
      offset += this->data.entsize;
    }

    return atoms;
  }

  virtual PtrT encodedSize() const override {
    return this->data.count * this->data.entsize;
  }

  std::list<IvarAtom<A>> entries;
};

/// @brief Represents a class_data_t
template <class A>
class ClassDataAtom final
    : public Atom<typename A::P, Objc::class_data_t<typename A::P>> {
  using P = A::P;
  using PtrT = P::PtrT;
  using DataT = Objc::class_data_t<P>;

public:
  ClassDataAtom(DataT data)
      : Atom<P, DataT>(data), ivarLayout(&this->data.ivarLayout),
        name(&this->data.name), baseMethods(&this->data.baseMethods),
        baseProtocols(&this->data.baseProtocols), ivars(&this->data.ivars),
        weakIvarLayout(&this->data.weakIvarLayout),
        baseProperties(&this->data.baseProperties) {}

  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    return {
        {(AtomBase<P> *)&ivarLayout, (PtrT)offsetof(DataT, ivarLayout)},
        {(AtomBase<P> *)&name, (PtrT)offsetof(DataT, name)},
        {(AtomBase<P> *)&baseMethods, (PtrT)offsetof(DataT, baseMethods)},
        {(AtomBase<P> *)&baseProtocols, (PtrT)offsetof(DataT, baseProtocols)},
        {(AtomBase<P> *)&ivars, (PtrT)offsetof(DataT, ivars)},
        {(AtomBase<P> *)&weakIvarLayout, (PtrT)offsetof(DataT, weakIvarLayout)},
        {(AtomBase<P> *)&baseProperties,
         (PtrT)offsetof(DataT, baseProperties)}};
  }

  FieldRefAtom<P, IvarLayoutAtom<P>> ivarLayout;
  FieldRefAtom<P, StringAtom<P>> name;
  FieldRefAtom<P, MethodListAtom<P>> baseMethods;
  FieldRefAtom<P, ProtocolListAtom<A>> baseProtocols;
  FieldRefAtom<P, IvarListAtom<A>> ivars;
  FieldRefAtom<P, IvarLayoutAtom<P>> weakIvarLayout;
  FieldRefAtom<P, PropertyListAtom<P>> baseProperties;
};

/// @brief Represents a class_t
template <class A>
class ClassAtom final
    : public Atom<typename A::P, Objc::class_t<typename A::P>> {
  using P = A::P;
  using PtrT = P::PtrT;
  using DataT = Objc::class_t<P>;

public:
  ClassAtom(DataT data)
      : Atom<P, DataT>(data), isa(&this->data.isa),
        superclass(&this->data.superclass), classData(&this->data.data) {}

  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    return {{(AtomBase<P> *)&isa, (PtrT)offsetof(DataT, isa)},
            {(AtomBase<P> *)&superclass, (PtrT)offsetof(DataT, superclass)},
            {(AtomBase<P> *)&classData, (PtrT)offsetof(DataT, data)}};
  }

  virtual void propagate() override {
    // need to preserve the extra bits in the data field
    PtrT bits = this->data.data & DataT::bitsMask;
    Atom<P, DataT>::propagate();
    this->data.data |= bits;
  }

  BindRefAtom<P, ClassAtom<A>> isa;
  BindRefAtom<P, ClassAtom<A>> superclass;
  FieldRefAtom<P, ClassDataAtom<A>> classData;
};

/// @brief Represents a category_t
template <class A>
class CategoryAtom final
    : public Atom<typename A::P, Objc::category_t<typename A::P>> {
  using P = A::P;
  using PtrT = P::PtrT;
  using DataT = Objc::category_t<P>;

public:
  CategoryAtom(DataT data, bool hasClassProperties)
      : Atom<P, DataT>(data), hasClassProperties(hasClassProperties),
        name(&this->data.name), cls(&this->data.cls),
        instanceMethods(&this->data.instanceMethods),
        classMethods(&this->data.classMethods),
        protocols(&this->data.protocols),
        instanceProperties(&this->data.instanceProperties),
        _classProperties(&this->data._classProperties) {}

  virtual std::vector<std::pair<AtomBase<P> *, PtrT>>
  getAtoms() const override {
    return {{(AtomBase<P> *)&name, (PtrT)offsetof(DataT, name)},
            {(AtomBase<P> *)&cls, (PtrT)offsetof(DataT, cls)},
            {(AtomBase<P> *)&instanceMethods,
             (PtrT)offsetof(DataT, instanceMethods)},
            {(AtomBase<P> *)&classMethods, (PtrT)offsetof(DataT, classMethods)},
            {(AtomBase<P> *)&protocols, (PtrT)offsetof(DataT, protocols)},
            {(AtomBase<P> *)&instanceProperties,
             (PtrT)offsetof(DataT, instanceProperties)},
            {(AtomBase<P> *)&_classProperties,
             (PtrT)offsetof(DataT, _classProperties)}};
  }

  virtual PtrT encodedSize() const override {
    if (hasClassProperties) {
      return offsetof(DataT, _classProperties) +
             sizeof(DataT::_classProperties);
    } else {
      return offsetof(DataT, instanceProperties) +
             sizeof(DataT::instanceProperties);
    }
  }

  FieldRefAtom<P, StringAtom<P>> name;
  BindRefAtom<P, ClassAtom<A>> cls;
  FieldRefAtom<P, MethodListAtom<P>> instanceMethods;
  FieldRefAtom<P, MethodListAtom<P>> classMethods;
  FieldRefAtom<P, ProtocolListAtom<A>> protocols;
  FieldRefAtom<P, PropertyListAtom<P>> instanceProperties;

  FieldRefAtom<P, PropertyListAtom<P>> _classProperties;

  bool hasClassProperties;
};

#pragma endregion StructureAtoms

} // namespace DyldExtractor::Converter::ObjcFixer

#endif // __CONVERTER_OBJC_ATOMS__

//===- lib/ReaderWriter/PECOFF/ReaderCOFF.cpp -----------------------------===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// *******************************
// ** COFFer code extension WIP **
// **      Bradley Dorney       **
// *******************************
//
//===----------------------------------------------------------------------===//

#include "Atoms.h"
#include "lld/Core/Alias.h"
#include "lld/Core/File.h"
#include "lld/Core/Reader.h"
#include "lld/Driver/Driver.h"
#include "lld/ReaderWriter/PECOFFLinkingContext.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileOutputBuffer.h"
#include "llvm/Support/FileUtilities.h"
#include "llvm/Support/Memory.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/StringSaver.h"
#include "llvm/Support/raw_ostream.h"
// *COFFer*
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCRelocationInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/Format.h"
#include <unordered_set>
// *End COFFer*
#include <algorithm>
#include <map>
#include <mutex>
#include <set>
#include <system_error>
#include <vector>

#define DEBUG_TYPE "ReaderCOFF"

using lld::pecoff::COFFBSSAtom;
using lld::pecoff::COFFDefinedAtom;
using lld::pecoff::COFFDefinedFileAtom;
using lld::pecoff::COFFUndefinedAtom;
using llvm::object::coff_aux_section_definition;
using llvm::object::coff_aux_weak_external;
using llvm::object::coff_relocation;
using llvm::object::coff_section;
using llvm::object::coff_symbol;
using llvm::support::ulittle32_t;

using namespace lld;

namespace {

class BumpPtrStringSaver final : public llvm::StringSaver {
public:
  BumpPtrStringSaver() : llvm::StringSaver(_alloc) {}
  const char *saveImpl(StringRef Str) override {
    std::lock_guard<std::mutex> lock(_allocMutex);
    return llvm::StringSaver::saveImpl(Str);
  }

private:
  llvm::BumpPtrAllocator _alloc;
  std::mutex _allocMutex;
};

class FileCOFF : public File {
private:
  typedef std::vector<llvm::object::COFFSymbolRef> SymbolVectorT;
  typedef std::map<const coff_section *, SymbolVectorT> SectionToSymbolsT;

public:
  FileCOFF(std::unique_ptr<MemoryBuffer> mb, PECOFFLinkingContext &ctx)
    : File(mb->getBufferIdentifier(), kindObject), _mb(std::move(mb)),
      _compatibleWithSEH(false), _ordinal(1),
      _machineType(llvm::COFF::MT_Invalid), _ctx(ctx) {}

  std::error_code doParse() override;
  bool isCompatibleWithSEH() const { return _compatibleWithSEH; }
  llvm::COFF::MachineTypes getMachineType() { return _machineType; }

  const AtomVector<DefinedAtom> &defined() const override {
    return _definedAtoms;
  }

  const AtomVector<UndefinedAtom> &undefined() const override {
    return _undefinedAtoms;
  }

  const AtomVector<SharedLibraryAtom> &sharedLibrary() const override {
    return _sharedLibraryAtoms;
  }

  const AtomVector<AbsoluteAtom> &absolute() const override {
    return _absoluteAtoms;
  }

  void beforeLink() override;

  void addUndefinedSymbol(StringRef sym) {
    _undefinedAtoms.push_back(new (_alloc) COFFUndefinedAtom(*this, sym));
  }

  AliasAtom *createAlias(StringRef name, const DefinedAtom *target, int cnt);
  void createAlternateNameAtoms();
  std::error_code parseDirectiveSection(StringRef directives);

  mutable llvm::BumpPtrAllocator _alloc;

private:
  std::error_code readSymbolTable(SymbolVectorT &result);
  ///
  // COFFer extensions
  ///
  pecoff::COFFSharedLibraryAtom *addSharedLibraryAtom(uint16_t hint,
    StringRef symbolName,
    StringRef importName,
    StringRef dllName) {
    auto *atom = new (_alloc)
      pecoff::COFFSharedLibraryAtom(*this, hint, symbolName, importName, dllName);
    _sharedLibraryAtoms.push_back(atom);
    return atom;
  }
  std::error_code FileCOFF::findSectionContaining(uint32_t targetAddress,
    llvm::object::SectionRef &result,
    uint32_t &sectionNumber);
  ErrorOr<llvm::object::COFFSymbolRef>
  generateDefinedSymbol(uint32_t address,
                         bool forceCode = false,
                         bool discard = false);
  ErrorOr<llvm::object::COFFSymbolRef>
  FileCOFF::generateAbsoluteSymbol(uint32_t value);
  std::error_code
  makeUnnamedSymbol(uint32_t RVA,
                    SymbolVectorT &result,
                    bool forceCode = false,
                    bool discard = false);
  ErrorOr<llvm::object::COFFSymbolRef> generateUndefSymbol();
  std::error_code generateSectionSymbols(SymbolVectorT &result);
  std::error_code generateMiscSymbols(SymbolVectorT &result);
  std::error_code deleteSymbol(llvm::object::COFFSymbolRef &symbol,
                               SymbolVectorT &result);
  std::error_code readSEHTable(SymbolVectorT &result);
  std::error_code readImportTable(SymbolVectorT &result);
  std::error_code readExportTable(SymbolVectorT &result);
  std::error_code
  getBaseRelocatedSymbol(const llvm::object::BaseRelocRef &rel,
                         uintptr_t &result);
  std::error_code readBaseRelocationTable(SymbolVectorT &result);
  std::error_code FileCOFF::addBaseRelocationReference(
                            const llvm::object::BaseRelocRef &rel,
                            const coff_section *section);
  std::error_code FileCOFF::addBaseRelocationReferenceToAtoms();
  std::error_code FileCOFF::parseAssembly(SymbolVectorT &result);
  std::error_code FileCOFF::addRelativeRelocationReference(
                            const uintptr_t rel,
                            const uintptr_t target,
                            const coff_section *section);
  std::error_code FileCOFF::addRelativeRelocationReferenceToAtoms();
  std::map<uintptr_t, uintptr_t> _relativeRelocationRVA;
  std::map<uintptr_t, llvm::object::COFFSymbolRef> _RVASymbol;
  std::map<llvm::object::COFFSymbolRef, pecoff::COFFSharedLibraryAtom *> _importSymbolAtom;
  const llvm::object::pe32_header *_PEHeader;
  ///
  // End COFFer extensions
  ///

  void createAbsoluteAtoms(const SymbolVectorT &symbols,
                           std::vector<const AbsoluteAtom *> &result);

  std::error_code
  createUndefinedAtoms(const SymbolVectorT &symbols,
                       std::vector<const UndefinedAtom *> &result);

  std::error_code
  createDefinedSymbols(const SymbolVectorT &symbols,
                       std::vector<const DefinedAtom *> &result);

  std::error_code cacheSectionAttributes();
  std::error_code maybeCreateSXDataAtoms();

  std::error_code
  AtomizeDefinedSymbolsInSection(const coff_section *section,
                                 SymbolVectorT &symbols,
                                 std::vector<COFFDefinedFileAtom *> &atoms);

  std::error_code
  AtomizeDefinedSymbols(SectionToSymbolsT &definedSymbols,
                        std::vector<const DefinedAtom *> &definedAtoms);

  std::error_code findAtomAt(const coff_section *section,
                             uint32_t targetAddress,
                             COFFDefinedFileAtom *&result,
                             uint32_t &offsetInAtom);

  std::error_code getAtomBySymbolIndex(uint32_t index, Atom *&ret);

  std::error_code
  addRelocationReference(const coff_relocation *rel,
                         const coff_section *section);

  std::error_code getSectionContents(StringRef sectionName,
                                     ArrayRef<uint8_t> &result);
  std::error_code getReferenceArch(Reference::KindArch &result);
  std::error_code addRelocationReferenceToAtoms();
  std::error_code findSection(StringRef name, const coff_section *&result);
  StringRef ArrayRefToString(ArrayRef<uint8_t> array);
  uint64_t getNextOrdinal();

  std::unique_ptr<const llvm::object::COFFObjectFile> _obj;
  std::unique_ptr<MemoryBuffer> _mb;
  AtomVector<DefinedAtom> _definedAtoms;
  AtomVector<UndefinedAtom> _undefinedAtoms;
  AtomVector<SharedLibraryAtom> _sharedLibraryAtoms;
  AtomVector<AbsoluteAtom> _absoluteAtoms;

  // The target type of the object.
  Reference::KindArch _referenceArch;

  // True if the object has "@feat.00" symbol.
  bool _compatibleWithSEH;

  // A map from symbol to its name. All symbols should be in this map except
  // unnamed ones.
  std::map<llvm::object::COFFSymbolRef, StringRef> _symbolName;

  // A map from symbol to its resultant atom.
  std::map<llvm::object::COFFSymbolRef, Atom *> _symbolAtom;

  // A map from symbol to its aux symbol.
  std::map<llvm::object::COFFSymbolRef, llvm::object::COFFSymbolRef> _auxSymbol;

  // A map from section to its atoms.
  std::map<const coff_section *, std::vector<COFFDefinedFileAtom *>>
  _sectionAtoms;

  // A set of COMDAT sections.
  std::set<const coff_section *> _comdatSections;

  // A map to get whether the section allows its contents to be merged or not.
  std::map<const coff_section *, DefinedAtom::Merge> _merge;

  // COMDAT associative sections
  std::multimap<const coff_section *, const coff_section *> _association;

  // A sorted map to find an atom from a section and an offset within
  // the section.
  std::map<const coff_section *, std::multimap<uint32_t, COFFDefinedAtom *>>
      _definedAtomLocations;

  uint64_t _ordinal;
  llvm::COFF::MachineTypes _machineType;
  PECOFFLinkingContext &_ctx;
  mutable BumpPtrStringSaver _stringSaver;
};

// Converts the COFF symbol attribute to the LLD's atom attribute.
Atom::Scope getScope(llvm::object::COFFSymbolRef symbol) {
  switch (symbol.getStorageClass()) {
  case llvm::COFF::IMAGE_SYM_CLASS_EXTERNAL:
    return Atom::scopeGlobal;
  case llvm::COFF::IMAGE_SYM_CLASS_STATIC:
  case llvm::COFF::IMAGE_SYM_CLASS_LABEL:
    return Atom::scopeTranslationUnit;
  }
  llvm_unreachable("Unknown scope");
}

DefinedAtom::ContentType getContentType(const coff_section *section) {
  if (section->Characteristics & llvm::COFF::IMAGE_SCN_CNT_CODE)
    return DefinedAtom::typeCode;
  if (section->Characteristics & llvm::COFF::IMAGE_SCN_CNT_INITIALIZED_DATA)
    return DefinedAtom::typeData;
  if (section->Characteristics & llvm::COFF::IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    return DefinedAtom::typeZeroFill;
  return DefinedAtom::typeUnknown;
}

DefinedAtom::ContentPermissions getPermissions(const coff_section *section) {
  if (section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_READ &&
      section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_WRITE)
    return DefinedAtom::permRW_;
  if (section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_READ &&
      section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE)
    return DefinedAtom::permR_X;
  if (section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_READ)
    return DefinedAtom::permR__;
  return DefinedAtom::perm___;
}

/// Returns the alignment of the section. The contents of the section must be
/// aligned by this value in the resulting executable/DLL.
DefinedAtom::Alignment getAlignment(const coff_section *section) {
  if (section->Characteristics & llvm::COFF::IMAGE_SCN_TYPE_NO_PAD)
    return 1;

  // Bit [20:24] contains section alignment information. We need to decrease
  // the value stored by 1 in order to get the real exponent (e.g, ALIGN_1BYTE
  // is 0x00100000, but the exponent should be 0)
  uint32_t characteristics = (section->Characteristics >> 20) & 0xf;

  // If all bits are off, we treat it as if ALIGN_1BYTE was on. The PE/COFF spec
  // does not say anything about this case, but CVTRES.EXE does not set any bit
  // in characteristics[20:24], and its output is intended to be copied to .rsrc
  // section with no padding, so I think doing this is the right thing.
  if (characteristics == 0)
    return 1;

  uint32_t powerOf2 = characteristics - 1;
  return 1 << powerOf2;
}

DefinedAtom::Merge getMerge(const coff_aux_section_definition *auxsym) {
  switch (auxsym->Selection) {
  case llvm::COFF::IMAGE_COMDAT_SELECT_NODUPLICATES:
    return DefinedAtom::mergeNo;
  case llvm::COFF::IMAGE_COMDAT_SELECT_ANY:
    return DefinedAtom::mergeAsWeakAndAddressUsed;
  case llvm::COFF::IMAGE_COMDAT_SELECT_EXACT_MATCH:
    // TODO: This mapping is wrong. Fix it.
    return DefinedAtom::mergeByContent;
  case llvm::COFF::IMAGE_COMDAT_SELECT_SAME_SIZE:
    return DefinedAtom::mergeSameNameAndSize;
  case llvm::COFF::IMAGE_COMDAT_SELECT_LARGEST:
    return DefinedAtom::mergeByLargestSection;
  case llvm::COFF::IMAGE_COMDAT_SELECT_ASSOCIATIVE:
  case llvm::COFF::IMAGE_COMDAT_SELECT_NEWEST:
    // FIXME: These attributes has more complicated semantics than the regular
    // weak symbol. These are mapped to mergeAsWeakAndAddressUsed for now
    // because the core linker does not support them yet. We eventually have
    // to implement them for full COFF support.
    return DefinedAtom::mergeAsWeakAndAddressUsed;
  default:
    llvm_unreachable("Unknown merge type");
  }
}

StringRef getMachineName(llvm::COFF::MachineTypes Type) {
  switch (Type) {
  default: llvm_unreachable("unsupported machine type");
  case llvm::COFF::IMAGE_FILE_MACHINE_ARMNT:
    return "ARM";
  case llvm::COFF::IMAGE_FILE_MACHINE_I386:
    return "X86";
  case llvm::COFF::IMAGE_FILE_MACHINE_AMD64:
    return "X64";
  }
}

std::error_code FileCOFF::doParse() {
  auto binaryOrErr = llvm::object::createBinary(_mb->getMemBufferRef());
  if (std::error_code ec = binaryOrErr.getError())
    return ec;
  std::unique_ptr<llvm::object::Binary> bin = std::move(binaryOrErr.get());

  _obj.reset(dyn_cast<const llvm::object::COFFObjectFile>(bin.get()));
  if (!_obj)
    return make_error_code(llvm::object::object_error::invalid_file_type);
  bin.release();

  _machineType = static_cast<llvm::COFF::MachineTypes>(_obj->getMachine());

  if (getMachineType() != llvm::COFF::IMAGE_FILE_MACHINE_UNKNOWN &&
      getMachineType() != _ctx.getMachineType()) {
    return make_dynamic_error_code(Twine("module machine type '") +
                                   getMachineName(getMachineType()) +
                                   "' conflicts with target machine type '" +
                                   getMachineName(_ctx.getMachineType()) + "'");
  }

  if (std::error_code ec = getReferenceArch(_referenceArch))
    return ec;
	
  // *COFFer* Get optional header, which also distinguishes between object and image.
  if (_obj->getSizeOfOptionalHeader() == 0) _PEHeader = nullptr;
  else if (auto ec = _obj->getPE32Header(_PEHeader)) return ec;
  else if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  // Read the symbol table and atomize them if possible. Defined atoms
  // cannot be atomized in one pass, so they will be not be atomized but
  // added to symbolToAtom.
  SymbolVectorT symbols;
  if (std::error_code ec = readSymbolTable(symbols))
    return ec;
  // *COFFer* Generate symbol table entries for PE/COFF images which lack them.
  if (_PEHeader) {
    /*if (std::error_code ec = readYAMLSymbolTable(*fileYAMLRef*, symbols)) *COFFer todo*
      return ec;*/
    if (std::error_code ec = generateSectionSymbols(symbols))
      return ec;
    if (std::error_code ec = generateMiscSymbols(symbols))
      return ec;
    if (std::error_code ec = readExportTable(symbols))
      return ec;
    if (std::error_code ec = readImportTable(symbols))
      return ec;
    if (std::error_code ec = readSEHTable(symbols))
      return ec;
    if (std::error_code ec = readBaseRelocationTable(symbols))
      return ec;
    if (std::error_code ec = parseAssembly(symbols))
      return ec;
  }

  createAbsoluteAtoms(symbols, _absoluteAtoms);
  if (std::error_code ec =
      createUndefinedAtoms(symbols, _undefinedAtoms))
    return ec;
  if (std::error_code ec = createDefinedSymbols(symbols, _definedAtoms))
    return ec;
  if (std::error_code ec = addRelocationReferenceToAtoms())
    return ec;
  // *COFFer*
  if (_PEHeader) {
    /*if (std::error_code ec = addYAMLRelocationReferenceToAtoms(*fileYAMLRef*)) *COFFer todo*
      return ec;*/
    if (std::error_code ec = addBaseRelocationReferenceToAtoms())
      return ec;
    if (std::error_code ec = addRelativeRelocationReferenceToAtoms())
      return ec;
  }
  if (std::error_code ec = maybeCreateSXDataAtoms())
    return ec;

  // ** COFFer debug dump **
  std::unique_ptr<Writer> YAML;
  YAML = createWriterYAML(_ctx);
  YAML.get()->writeFile(*this, ".\\COFFerInputDump.txt");

  // Check for /SAFESEH.
  if (_ctx.requireSEH() && !isCompatibleWithSEH()) {
    llvm::errs() << "/SAFESEH is specified, but "
                 << _mb->getBufferIdentifier()
                 << " is not compatible with SEH.\n";
    return llvm::object::object_error::parse_failed;
  }
  return std::error_code();
}

void FileCOFF::beforeLink() {
  // Acquire the mutex to mutate _ctx.
  std::lock_guard<std::recursive_mutex> lock(_ctx.getMutex());
  std::set<StringRef> undefSyms;

  // Interpret .drectve section if the section has contents.
  ArrayRef<uint8_t> directives;
  if (getSectionContents(".drectve", directives))
    return;
  if (!directives.empty()) {
    std::set<StringRef> orig;
    for (StringRef sym : _ctx.initialUndefinedSymbols())
      orig.insert(sym);
    if (parseDirectiveSection(ArrayRefToString(directives)))
      return;
    for (StringRef sym : _ctx.initialUndefinedSymbols())
      if (orig.count(sym) == 0)
        undefSyms.insert(sym);
  }

  // Add /INCLUDE'ed symbols to the file as if they existed in the
  // file as undefined symbols.
  for (StringRef sym : undefSyms) {
    addUndefinedSymbol(sym);
    _ctx.addDeadStripRoot(sym);
  }

  // One can define alias symbols using /alternatename:<sym>=<sym> option.
  // The mapping for /alternatename is in the context object. This helper
  // function iterate over defined atoms and create alias atoms if needed.
  createAlternateNameAtoms();

  // In order to emit SEH table, all input files need to be compatible with
  // SEH. Disable SEH if the file being read is not compatible.
  if (!isCompatibleWithSEH())
    _ctx.setSafeSEH(false);
}

/// Iterate over the symbol table to retrieve all symbols.
std::error_code
FileCOFF::readSymbolTable(SymbolVectorT &result) {
  for (uint32_t i = 0, e = _obj->getNumberOfSymbols(); i != e; ++i) {
    // Retrieve the symbol.
    ErrorOr<llvm::object::COFFSymbolRef> sym = _obj->getSymbol(i);
    StringRef name;
    if (std::error_code ec = sym.getError())
      return ec;
    if (sym->getSectionNumber() == llvm::COFF::IMAGE_SYM_DEBUG)
      goto next;
    result.push_back(*sym);

    if (std::error_code ec = _obj->getSymbolName(*sym, name))
      return ec;

    // Existence of the symbol @feat.00 indicates that object file is compatible
    // with Safe Exception Handling.
    if (name == "@feat.00") {
      _compatibleWithSEH = true;
      goto next;
    }

    // Cache the name.
    _symbolName[*sym] = name;

    // Symbol may be followed by auxiliary symbol table records. The aux
    // record can be in any format, but the size is always the same as the
    // regular symbol. The aux record supplies additional information for the
    // standard symbol. We do not interpret the aux record here, but just
    // store it to _auxSymbol.
    if (sym->getNumberOfAuxSymbols() > 0) {
      ErrorOr<llvm::object::COFFSymbolRef> aux = _obj->getSymbol(i + 1);
      if (std::error_code ec = aux.getError())
        return ec;
      _auxSymbol[*sym] = *aux;
    }
  next:
    i += sym->getNumberOfAuxSymbols();
  }
  return std::error_code();
}

///////////////////////////////
/// Begin COFFer extensions
/// These utilize "fake" object symbol table entries for the sake of being able
/// to reuse the rest of the code, but it's somewhat of a hack. Change later?

/// Given \p address as a RVA, generates a defined COFFSymbolRef. Executables only.
ErrorOr<llvm::object::COFFSymbolRef>
FileCOFF::generateDefinedSymbol(uint32_t address, bool forceCode, bool discard) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  auto *sym = new (_alloc)llvm::object::coff_symbol32();

  // Find the section containing the RVA.
  llvm::object::SectionRef Sec;
  uint32_t SectionNumber;
  if (auto ec = findSectionContaining(address, Sec, SectionNumber)) return ec;

  bool isCode = forceCode || Sec.isText();
  bool isExtern = isCode; // ** FIXME ??

  sym->Value = address - Sec.getAddress();
  sym->SectionNumber = SectionNumber;
  sym->Type = llvm::COFF::IMAGE_SYM_TYPE_NULL + isCode ?
    llvm::COFF::IMAGE_SYM_DTYPE_FUNCTION << llvm::COFF::SCT_COMPLEX_TYPE_SHIFT :
    llvm::COFF::IMAGE_SYM_DTYPE_NULL;
  // We'll borrow the Label class for marking discardable regions (like padders)
  sym->StorageClass = discard  ? llvm::COFF::IMAGE_SYM_CLASS_LABEL :
                      isExtern ? llvm::COFF::IMAGE_SYM_CLASS_EXTERNAL :
                                 llvm::COFF::IMAGE_SYM_CLASS_STATIC;
  sym->NumberOfAuxSymbols = 0; // ** maybe make weak extern here?

  return llvm::object::COFFSymbolRef(sym);
}

/// Generates an absolute COFFSymbolRef.
ErrorOr<llvm::object::COFFSymbolRef>
FileCOFF::generateAbsoluteSymbol(uint32_t value) {
  auto *sym = new (_alloc)llvm::object::coff_symbol32();

  bool isExtern = false; // ** FIXME what do?

  sym->Value = value;
  sym->SectionNumber = llvm::COFF::IMAGE_SYM_ABSOLUTE;
  sym->Type = llvm::COFF::IMAGE_SYM_TYPE_NULL;
  sym->StorageClass = isExtern ? llvm::COFF::IMAGE_SYM_CLASS_EXTERNAL :
                                 llvm::COFF::IMAGE_SYM_CLASS_STATIC;
  sym->NumberOfAuxSymbols = 0;

  return llvm::object::COFFSymbolRef(sym);
}

/// Streamlining helper function for generateDefinedSymbol. Unnamed only.
std::error_code 
FileCOFF::makeUnnamedSymbol(
  uint32_t address, SymbolVectorT &result, bool forceCode, bool discard) {
  // Generate an unnamed COFFSymbolRef; assume target is code.
  auto iter = _RVASymbol.find(address);
  if (iter == _RVASymbol.end()) {
    auto sym = address ? generateDefinedSymbol(address, forceCode, discard) :
                         generateAbsoluteSymbol(address); // ** FIXME what do?
    if (auto ec = sym.getError()) return ec;
    result.push_back(*sym);

    // Cache the RVA->Symbol mapping.
    _RVASymbol[address] = *sym;
  }
  else if (forceCode) {
    // Verify that the symbol's type is correct; if not, fix it.
    if (iter->second.getComplexType() !=
      llvm::COFF::IMAGE_SYM_DTYPE_FUNCTION) {
      llvm::errs() << "warning: fixing symbol type to code at "
                   << llvm::format("%x", address) << "\n";
      llvm::support::ulittle16_t *type;
      if (iter->second.isBigObj()) {
        type = &const_cast<llvm::object::coff_symbol32 *>(
          reinterpret_cast<const llvm::object::coff_symbol32 *>(
          iter->second.getRawPtr()))->Type;
      }
      else {
        type = &const_cast<llvm::object::coff_symbol16 *>(
          reinterpret_cast<const llvm::object::coff_symbol16 *>(
          iter->second.getRawPtr()))->Type;
      }
      *type = llvm::COFF::IMAGE_SYM_TYPE_NULL + (
        llvm::COFF::IMAGE_SYM_DTYPE_FUNCTION <<
        llvm::COFF::SCT_COMPLEX_TYPE_SHIFT);
    }
  }
  return std::error_code();
}

/// Generates an undefined COFFSymbolRef.
ErrorOr<llvm::object::COFFSymbolRef> FileCOFF::generateUndefSymbol() {
  auto *sym = new (_alloc)llvm::object::coff_symbol32();

  bool isCode = true; // ** FIXME How to detect if data? Undecorate name maybe?

  sym->Value = 0; // **
  sym->SectionNumber = llvm::COFF::IMAGE_SYM_UNDEFINED;
  sym->Type = llvm::COFF::IMAGE_SYM_TYPE_NULL + (isCode ?
              llvm::COFF::IMAGE_SYM_DTYPE_FUNCTION <<
              llvm::COFF::SCT_COMPLEX_TYPE_SHIFT :
              llvm::COFF::IMAGE_SYM_DTYPE_NULL);
  sym->StorageClass = llvm::COFF::IMAGE_SYM_CLASS_EXTERNAL;
  sym->NumberOfAuxSymbols = 0;

  return llvm::object::COFFSymbolRef(sym);
}

/// Generates COFFSymbolRefs for the sections. Executables only.
std::error_code FileCOFF::generateSectionSymbols(SymbolVectorT &result) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  int num = 0;
  for (const auto &Sec : _obj->sections()) {
    StringRef name;
    auto *sym = new (_alloc)llvm::object::coff_symbol32();
    auto *aux = new (_alloc)llvm::object::coff_symbol32();

    if (auto ec = Sec.getName(name)) return ec;
    auto *rawSec = reinterpret_cast<coff_section *>(Sec.getRawDataRefImpl().p);

    sym->Value = 0; // **
    sym->SectionNumber = num + 1; // 1 based (SectionNumber == 0 is undefined)
    sym->Type = llvm::COFF::IMAGE_SYM_TYPE_NULL;
    sym->StorageClass = llvm::COFF::IMAGE_SYM_CLASS_STATIC;
    sym->NumberOfAuxSymbols = 1;

    auto *asd = reinterpret_cast<coff_aux_section_definition *>(aux);
    asd->Length = Sec.getSize();
    asd->NumberOfRelocations = rawSec->NumberOfRelocations;
    asd->NumberOfLinenumbers = rawSec->NumberOfLinenumbers;
    asd->CheckSum = 0; // **
    asd->NumberLowPart = num; // 0 based (e.g. section 1 == 0)
    asd->Selection = 0; // COMDAT type (llvm::COFF::IMAGE_COMDAT_SELECT_xxx)
    //asd->NumberHighPart field only present in COFF bigobj

    auto symRef = llvm::object::COFFSymbolRef(sym);
    result.push_back(symRef);

    // Cache the name.
    _symbolName[symRef] = name;

    // Cache the auxiliary data mapping.
    _auxSymbol[symRef] = llvm::object::COFFSymbolRef(aux);
    
    // We do not cache the symbol in _RVASymbol because it will overlap with
    // the first symbol in the section.

    ++num;
  }
  return std::error_code();
}

/// Create symbols for miscellaneous references, such as entry point. Executables
/// only.
std::error_code
FileCOFF::generateMiscSymbols(SymbolVectorT &result) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  // Generate a symbol for the entry point if it does not already exist.
  auto Entry = static_cast<uintptr_t>(_PEHeader->AddressOfEntryPoint);
  if (_RVASymbol.count(Entry) == 0) {
    // Generate a static COFFSymbolRef.
    auto sym = generateDefinedSymbol(Entry);
    if (auto ec = sym.getError()) return ec;
    result.push_back(*sym);

    // Cache an assumed name.
    _symbolName[*sym] = StringRef("_start"); // ** FIXME

    // Cache the RVA->Symbol mapping.
    _RVASymbol[Entry] = *sym;
  }

  return std::error_code();
}

/// Deletes a symbol. Used for correcting false positives. Executables only.
std::error_code
FileCOFF::deleteSymbol(llvm::object::COFFSymbolRef &symbol, SymbolVectorT &result) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  // Make sure the symbol actually exists in the vector, and get its position.
  bool isInVector = false;
  int i = -1;
  for (auto &I : result) {
    ++i;
    if (symbol.getRawPtr() == I.getRawPtr()) {
      isInVector = true;
      break;
    }
  }
  if (!isInVector)
    return std::error_code();

  const coff_section *sec;
  if (std::error_code ec = _obj->getSection(symbol.getSectionNumber(), sec))
    return ec;

  // Erase from _RVASymbol.
  auto iter = _RVASymbol.find(symbol.getValue() + sec->VirtualAddress);
  if (iter != _RVASymbol.end()) _RVASymbol.erase(iter);

  // Erase from _symbolName.
  auto iter2 = _symbolName.find(symbol);
  if (iter2 != _symbolName.end()) _symbolName.erase(iter2);

  // Erase from _importSymbolAtom.
  auto iter3 = _importSymbolAtom.find(symbol);
  if (iter3 != _importSymbolAtom.end()) _importSymbolAtom.erase(iter3);

  // Erase from the symbol vector.
  result.erase(result.begin() + i);

  /* ** TODO mark for which symbols it's safe to delete? Or just don't care
  if (symbol.isBigObj()) {
    auto *sym32 = const_cast<llvm::object::coff_symbol32 *>(
      reinterpret_cast<const llvm::object::coff_symbol32 *>(
      symbol.getRawPtr()));
    delete sym32; // **
  }
  else {
    auto *sym16 = const_cast<llvm::object::coff_symbol16 *>(
      reinterpret_cast<const llvm::object::coff_symbol16 *>(
      symbol.getRawPtr()));
    delete sym16; // **
  }*/

  return std::error_code();
}

// ** COFFer todo
/// Iterate over the import table and create undefined symbols. Executables only.
std::error_code
FileCOFF::readImportTable(SymbolVectorT &result) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  // Regular imports
  for (const llvm::object::ImportDirectoryEntryRef &I : _obj->import_directories()) {
    uint32_t addressRVA;
    if (auto ec = I.getImportAddressTableRVA(addressRVA)) return ec;
    StringRef dllName;
    if (auto ec = I.getName(dllName)) return ec;

    int i = 0;
    for (const llvm::object::ImportedSymbolRef &J : I.imported_symbols()) {
      StringRef importName;
      if (auto ec = J.getSymbolName(importName)) return ec;
      uint16_t hint;
      if (std::error_code ec = J.getOrdinal(hint)) return ec;

      // Add a shared library atom for the import. This will be matched against
      // the shared library atom from the required import library to obtain the
      // correct symbol name if the import name is undecorated.
      auto *atom = addSharedLibraryAtom(hint, importName /* symbolName */,
                                        importName, dllName);
      if (importName.startswith("_") && importName.count("@") != 0) { /* ** TODO mark symbol as function? */ }
      if (/*isFunction ||*/ importName.startswith("?") || importName.startswith("@")) { /* ** TODO mark symbol already decorated */ }
      // ** FIXME if undecorated imports, parse directive /defaultlib:[dllName - .dll].lib (if file exists)

      // Generate a symbol entry for the associated .idata.
      uint32_t address = addressRVA + _obj->getBytesInAddress() * i;
      auto iter = _RVASymbol.find(address);
      if (iter == _RVASymbol.end()) {
        auto sym = generateDefinedSymbol(address);
        if (auto ec = sym.getError()) return ec;
        result.push_back(*sym);

        // Cache the RVA->Symbol mapping.
        _RVASymbol[address] = *sym;

        // Mark the symbol to be associated with the SharedLibraryAtom.
        _importSymbolAtom[*sym] = atom;
      }
      else {
        // Mark the symbol to be associated with the SharedLibraryAtom.
        _importSymbolAtom[iter->second] = atom;
      }

      ++i;
    }
  }

  // ** FIXME delay imports incomplete
  /*// Delay imports
  for (const llvm::object::DelayImportDirectoryEntryRef &I :
    _obj->delay_import_directories()) {
    StringRef Name;
    if (auto ec = I.getName(Name)) return ec;
    const llvm::object::delay_import_directory_table_entry *Table;
    if (auto ec = I.getDelayImportTable(Table)) return ec;
    //Table->Attributes
    //Table->ModuleHandle
    //Table->DelayImportAddressTable
    //Table->DelayImportNameTable
    //Table->BoundDelayImportTable
    //Table->UnloadDelayImportTable
    int Index = 0;
    for (const llvm::object::ImportedSymbolRef &S : I.imported_symbols()) {
      StringRef Sym;
      if (auto ec = S.getSymbolName(Sym)) return ec;
      if (Sym.empty()) continue;
      uint16_t Ordinal;
      if (auto ec = S.getOrdinal(Ordinal)) return ec;
      uint64_t Addr;
      if (auto ec = I.getImportAddress(Index++, Addr)) return ec;
      // ... todo, if we care
    }
  }*/

  return std::error_code();
}

/// Iterate over the export table and create defined symbols. Executables only.
std::error_code
FileCOFF::readExportTable(SymbolVectorT &result) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  for (const llvm::object::ExportDirectoryEntryRef &E :
    _obj->export_directories()) {
    StringRef name;
    uint32_t RVA;
    if (auto ec = E.getSymbolName(name)) return ec;
    if (auto ec = E.getExportRVA(RVA)) return ec;

    // Check if the referenced symbol has already been generated.
    auto iter = _RVASymbol.find(RVA);
    if (iter != _RVASymbol.end())
      return std::error_code();

    // Generate a COFF object symbol entry.
    auto sym = generateDefinedSymbol(RVA);
    if (auto ec = sym.getError()) return ec;
    result.push_back(*sym);

    // Cache the name.
    if (!name.empty()) {
      if (!((name.startswith("_") && name.count("@") != 0) ||
        name.startswith("?") || name.startswith("@")))
        llvm::errs() << "warning: export " << name << " is not decorated\n";
      _symbolName[*sym] = name;
    }
    
    // Cache the RVA->Symbol mapping.
    _RVASymbol[RVA] = *sym;
  }
  return std::error_code();
}

// ** COFFer todo
/// Iterate over the SEH table. Executables only.
std::error_code
FileCOFF::readSEHTable(SymbolVectorT &result) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;
  // if (SEH log config exists etc.) _compatibleWithSEH = true;
  // ... todo
  return std::error_code();
}

/// Get the RVA of the symbol \p rel base relocation is to be applied to.
/// Executables only.
std::error_code
FileCOFF::getBaseRelocatedSymbol(const llvm::object::BaseRelocRef &rel,
                                 uintptr_t &result) {
  // Get the raw pointer the relocation applies to.
  uintptr_t RVA, FileOffset, Reference;
  if (auto ec = rel.getRVA(RVA)) return ec;
  if (auto ec = _obj->getRvaPtr(RVA, FileOffset)) return ec;
  Reference = llvm::support::endian::read32le(
              reinterpret_cast<const void*>(FileOffset));

  // Convert Reference to RVA based on Type.
  uint8_t Type;
  if (auto ec = rel.getType(Type)) return ec;
  switch (Type) {
  case llvm::COFF::IMAGE_REL_BASED_HIGHLOW:
    Reference -= _PEHeader->ImageBase;
    break;
  case llvm::COFF::IMAGE_REL_BASED_DIR64:
  default:
    return llvm::object::object_error::parse_failed;
  }

  // Store the result.
  result = Reference;
  return std::error_code();
}

/// Iterate over the base relocation table and create symbols. Executables
/// only. Use after the other symbol creation functions, as this is not able
/// to determine names. NOTE: This splits up things such as functions' switch
/// jump tables and switch indirect tables into their own symbols. Probably
/// doesn't matter, but not sure if correct with spec? ** TODO look into
std::error_code
FileCOFF::readBaseRelocationTable(SymbolVectorT &result) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  for (const auto &I : _obj->base_relocs()) {
    uint8_t Type;
    if (auto ec = I.getType(Type)) return ec;
    // IMAGE_REL_BASED_ABSOLUTE is used as a padder.
    if (Type == llvm::COFF::IMAGE_REL_BASED_ABSOLUTE) continue;

    uintptr_t Reference;
    if (auto ec = getBaseRelocatedSymbol(I, Reference)) return ec;
    if (auto ec = makeUnnamedSymbol(Reference, result)) return ec;
  }
  return std::error_code();
}

/// Iterate through the sections to find the one containing \p targetAddress
/// as a RVA. Executables only.
std::error_code
FileCOFF::findSectionContaining(uint32_t targetAddress,
                                llvm::object::SectionRef &result,
                                uint32_t &sectionNumber) {
  // Executable images have sections with non-zero virtual addresses that
  // are located sequentially with no overlap. Objects generally do not.
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  int num = 0;
  for (const auto &Sec : _obj->sections()) {
    ++num;

    const coff_section *_Sec;
    if (auto ec = _obj->getSection(num, _Sec)) return ec;
    if (targetAddress >= Sec.getAddress() &&
        targetAddress < Sec.getAddress() + _Sec->VirtualSize) {
      result = Sec;
      sectionNumber = num;
      return std::error_code();
    }
  }
  llvm::errs() << "Could not find section containing RVA "
               << llvm::format("%x", targetAddress) << ".\n";
  return llvm::object::object_error::parse_failed;
}

/// Add relocation information to an atom based on \p rel. Executables only.
/// \p rel is a base relocation entry, and \p atoms are all the atoms
/// defined in the \p section.
std::error_code FileCOFF::addBaseRelocationReference(
                          const llvm::object::BaseRelocRef &rel,
                          const coff_section *section) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  uint8_t Type;
  uint32_t RVA;
  if (std::error_code ec = rel.getRVA(RVA)) return ec;
  if (std::error_code ec = rel.getType(Type)) return ec;

  // Skip if rel is a padder entry.
  if (Type == llvm::COFF::IMAGE_REL_BASED_ABSOLUTE) return std::error_code();

  uintptr_t Reference;
  if (auto ec = getBaseRelocatedSymbol(rel, Reference)) return ec;

  uint32_t SectionNumber;
  llvm::object::SectionRef Sec;
  if (auto ec = findSectionContaining(Reference, Sec, SectionNumber)) return ec;
  const coff_section *sSection = _obj->getCOFFSection(Sec);

  // Convert from base relocation type to object relocation type.
  uint16_t newType;
  switch (Type) {
  case llvm::COFF::IMAGE_REL_BASED_HIGHLOW:
    newType = llvm::COFF::IMAGE_REL_I386_DIR32;
    break;
  case llvm::COFF::IMAGE_REL_BASED_DIR64:
    newType = llvm::COFF::IMAGE_REL_AMD64_ADDR64; // **
    break;
  default:
    return llvm::object::object_error::parse_failed;
  }

  COFFDefinedFileAtom *targetAtom, *atom;
  uint32_t offsetInAtom;
  if (auto ec = findAtomAt(sSection,
                Reference - sSection->VirtualAddress,
                targetAtom, offsetInAtom))
    return ec;

  if (auto ec = findAtomAt(section, RVA - section->VirtualAddress,
                atom, offsetInAtom))
    return ec;
  atom->addReference(llvm::make_unique<SimpleReference>(
    Reference::KindNamespace::COFF, _referenceArch,
    newType, offsetInAtom, targetAtom, 0));
  return std::error_code();
}

/// Add relocation information to atoms. Executables only.
std::error_code FileCOFF::addBaseRelocationReferenceToAtoms() {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  // Base relocation entries are defined in the .reloc section.
  for (const auto &I : _obj->base_relocs()) {
    uint8_t Type;
    uint32_t RVA;
    if (std::error_code ec = I.getRVA(RVA)) return ec;
    if (std::error_code ec = I.getType(Type)) return ec;
    
    // Skip if padder entry.
    if (Type == llvm::COFF::IMAGE_REL_BASED_ABSOLUTE) continue;

    uint32_t SectionNumber;
    llvm::object::SectionRef Sec;
    if (auto ec = findSectionContaining(RVA, Sec, SectionNumber)) return ec;
    const coff_section *section = _obj->getCOFFSection(Sec);

    // Skip if there's no atom for the section. Currently we do not create any
    // atoms for some sections, such as "debug$S", and such sections need to
    // be skipped here too.
    if (_sectionAtoms.find(section) == _sectionAtoms.end()) continue;

    if (auto ec = addBaseRelocationReference(I, section)) return ec;
  }

  return std::error_code();
}

// ** COFFer todo - code needs cleaning
/// Disassemble and scan for instructions which need relative relocations
/// and/or symbols generated for. Executables only.
std::error_code FileCOFF::parseAssembly(SymbolVectorT &result) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  // Figure out the target triple.
  llvm::Triple TheTriple("unknown-unknown-unknown");
  TheTriple.setArch(llvm::Triple::ArchType(_obj->getArch()));
  if (_obj->getArch() == llvm::Triple::thumb)
    TheTriple.setTriple("thumbv7-windows");

  // Get the target specific parser.
  std::string Error;
  const llvm::Target *TheTarget = llvm::TargetRegistry::lookupTarget("" /* arch */, TheTriple,
    Error);
  if (!TheTarget) {
    llvm::errs() << "error: " << Error << "\n";
    return llvm::object::object_error::arch_not_found;
  }

  // Package up features to be passed to target/subtarget
  /*std::string FeaturesStr;
  if (MAttrs.size()) {
    SubtargetFeatures Features;
    for (unsigned i = 0; i != MAttrs.size(); ++i)
      Features.AddFeature(MAttrs[i]);
    FeaturesStr = Features.getString();
  }*/

  std::string TripleName = TheTriple.getTriple();

  // Set up disassembler.
  std::unique_ptr<const llvm::MCRegisterInfo> MRI(
    TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    llvm::errs() << "error: no register info for target " << TripleName << "\n";
    return llvm::object::object_error::parse_failed;
  }

  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
    TheTarget->createMCAsmInfo(*MRI, TripleName));
  if (!AsmInfo) {
    llvm::errs() << "error: no assembly info for target " << TripleName << "\n";
    return llvm::object::object_error::parse_failed;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
    TheTarget->createMCSubtargetInfo(TripleName, "" /* CPU */, "" /* Features */));
  if (!STI) {
    llvm::errs() << "error: no subtarget info for target " << TripleName << "\n";
    return llvm::object::object_error::parse_failed;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(TheTarget->createMCInstrInfo());
  if (!MII) {
    llvm::errs() << "error: no instruction info for target " << TripleName << "\n";
    return llvm::object::object_error::parse_failed;
  }

  std::unique_ptr<const llvm::MCObjectFileInfo> MOFI(new llvm::MCObjectFileInfo);
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), MOFI.get());

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
    TheTarget->createMCDisassembler(*STI, Ctx));

  if (!DisAsm) {
    llvm::errs() << "error: no disassembler for target " << TripleName << "\n";
    return llvm::object::object_error::parse_failed;
  }

  std::unique_ptr<const llvm::MCInstrAnalysis> MIA(
    TheTarget->createMCInstrAnalysis(MII.get()));

  // Some older/nonstandard PECOFF files have executable code within RW data
  // sections. If there are calls to other sections, make sure the sections
  // are disassembled.
  std::map<llvm::object::SectionRef, bool> SecHasCode;

  // Make a set of all your base relocations. This will be used for sanity
  // checking of detected instructions; if pcrel32 overlaps with a base relocation
  // that means it was misinterpreted pointer data, usually a jump table for
  // a switch statement. Indirect tables for switch statements can still be an
  // issue if we test for low-index opcodes or the switch table has many cases.
  std::unordered_set<uint32_t> BaseRelocs;
  BaseRelocs.reserve(34000 * 4); // ** FIXME implement an actual count?
  for (const auto &I : _obj->base_relocs()) {
    uint8_t Type;
    uint32_t RVA;
    if (std::error_code ec = I.getType(Type)) return ec;
    if (Type == 0) continue;  // Skip padder entries
    if (std::error_code ec = I.getRVA(RVA)) return ec;
    for (int i = 0; i < 4; ++i)
      BaseRelocs.insert(RVA + i);
  }

  std::map<uintptr_t, uintptr_t> jumps;

  for (const llvm::object::SectionRef &Section : _obj->sections()) {
    if ((!Section.isText() && !SecHasCode[Section]) || Section.isVirtual())
      continue;

    uint64_t SectionAddr = Section.getAddress();
    uint64_t SectSize = Section.getSize();
    if (!SectSize)
      continue;

    StringRef name;
    if (auto ec = Section.getName(name)) return ec;

    SmallString<40> Comments;
    llvm::raw_svector_ostream CommentStream(Comments);

    StringRef BytesStr;
    if (auto ec = Section.getContents(BytesStr)) return ec;
    ArrayRef<uint8_t> Bytes(reinterpret_cast<const uint8_t *>(BytesStr.data()),
                            BytesStr.size());

    uint64_t Size;
    uint64_t Index;

    uint64_t Start = 0;
    uint64_t End = SectSize;

    int32_t padCount = 0;
    uint64_t checkImpThunkStart = -1;
    uintptr_t checkImpThunkStartTarget = -1;
    int32_t numImportThunks = 0;

#ifndef NDEBUG
    raw_ostream &DebugOut = /* FIXME DebugFlag ? llvm::dbgs() :*/ llvm::nulls();
#else
    raw_ostream &DebugOut = llvm::nulls();
#endif
    
    for (Index = Start; Index < End; Index += Size) {
      llvm::MCInst Inst;
      if (DisAsm->getInstruction(Inst, Size, Bytes.slice(Index),
                                 SectionAddr + Index, DebugOut,
                                 CommentStream)) {
        Comments.clear();

        uintptr_t targetAddress = -1;
        uint32_t opcode = Inst.getOpcode();
        /*if (SectionAddr + Index == 0xB5060) {
          llvm::errs() << llvm::format("%8" PRIx64, SectionAddr + Index)
                       << " | opcode: " << opcode;
          for (uint32_t i = 0; i < Inst.getNumOperands(); ++i) {
            llvm::errs() << " | operand " << i << ": ";
            Inst.getOperand(i).print(llvm::dbgs());
          }
          llvm::errs() << "\n";
        }*/

        // ** \lib\Target\X86\X86GenInstrInfo.inc (TblGen'd) for opcode indexes
        // FIXME: include that file properly so we can use X86::etc. instead
      	// Indexes in this context are NOT the same as the actual opcodes! They
        // can also shift between llvm revisions!

        // Assume (multiple) preceding INT 3 instructions to be padder after
        // a function definition. This is not the case in non-standard data
        // sections containing code, however, so ignore those.
        if (opcode == 966 /* X86::INT3 */) {
          if (Section.isText())
            ++padCount;
        }
        else if (padCount > 0) {
          if (padCount >= 1) { // ** FIXME ensure this is a safe number
            uintptr_t currentLocation = SectionAddr + Index;

            // If your base relocation overlaps with a detected padder, then it
            // must have been misinterpreted, so skip.
            for (uint32_t i = currentLocation - padCount;
                 i < currentLocation; ++i) {
              if (BaseRelocs.count(i) != 0) {
                --padCount;
                llvm::errs() << "DISASM: warning: misinterpreted padder near "
                  << llvm::format("%8" PRIx64, SectionAddr + Index)
                  << "\n";
              }
            }
            if (padCount > 0) {
              // Generate a dummy static COFFSymbolRef for marking the padders
              // for trimming.
              if (auto ec = makeUnnamedSymbol(currentLocation - padCount,
                                              result, false, true))
                return ec;

              // Generate an unnamed static COFFSymbolRef; assume target is code.
              if (auto ec = makeUnnamedSymbol(currentLocation, result, true))
                return ec;
            }
          }
          padCount = 0;
        }

        if (checkImpThunkStart != -1 && opcode != 1137 /* X86::JMP32m */) {
          checkImpThunkStart = -1;
          numImportThunks = 0;
        }

        if (opcode == 384 /* X86::CALLpcrel32 */ ||
            opcode == 1143 /* X86::JMP_4 */) {
          // Get the pc-relative displacement.
          auto operand = Inst.getOperand(0).getImm();

          // Dummy value used in self-modifying call code, skip.
          if (operand == 0x12345678) continue;

          uintptr_t pointerAddress = SectionAddr + Index + 1;
                    targetAddress = pointerAddress + 4 + operand;

          // Check if your base relocation exists within the bounds of the
          // detected instruction. If so, this is likely a misinterpreted jump
          // table, so skip it. Also skip if target is out of bounds.
          bool skip = false;
          if (targetAddress < 0 || targetAddress > _PEHeader->SizeOfImage)
            skip = true;
          else {
            for (int i = Index; i < Size; ++i) {
              if (BaseRelocs.count(SectionAddr + i) != 0) {
                skip = true;
                break;
              }
            }
          }
          if (skip) {
            llvm::errs() << "DISASM: warning: skipping invalid pointer at "
                         << llvm::format("%x", pointerAddress) << " to "
                         << llvm::format("%x", targetAddress)  << "\n";
            continue;
          }

          if (opcode == 1143 /* X86::JMP_4 */) {
            // Cache the jump location and destination. We need to check this
            // after every symbol has been generated, post-process.
            jumps[pointerAddress] = targetAddress;

            // Skip generating symbol.
            targetAddress = -1;
            continue;
          }
          else {
            // Cache the address where a relocation needs to be added.
            _relativeRelocationRVA[pointerAddress] = targetAddress;
          }
        }
        else if (opcode == 378 /* X86::CALL32m */ ||
                 opcode == 1137 /* X86::JMP32m */) {
          // The only new information we can get from this check is if a call
          // targets a function in another section that isn't marked as code,
          // so it can be corrected. Otherwise, the base relocation parsing
          // handles relocation and symbol generation for these cases.
          // ** FIXME detect proper form of instruction for this pass correctly
          auto operand = Inst.getOperand(3).getImm();
          uintptr_t functionPointer = operand - _PEHeader->ImageBase;
          uintptr_t pointerAddress = SectionAddr + Index + 2;

          // Check if base relocations exist at the operand and the pointer,
          // but not at the opcode. If so, it is valid.
          if (BaseRelocs.count(SectionAddr + Index) == 0 &&
              BaseRelocs.count(pointerAddress) != 0) {
            if (opcode == 378 /* X86::CALL32m */ &&
                BaseRelocs.count(functionPointer) != 0) {
              // Generate a symbol for the pointer to pointer in case all your
              // base relocation to symbol pass wasn't performed.
              if (auto ec = makeUnnamedSymbol(functionPointer, result)) return ec;

              // Operand is pointer to pointer. Get base pointer to function.
              // Iterate over pointer table if detected.
              while (BaseRelocs.count(functionPointer) != 0) {
                _obj->getRvaPtr(functionPointer, targetAddress);
                targetAddress = llvm::support::endian::read32le(
                  reinterpret_cast<const void*>(targetAddress)) -
                  _PEHeader->ImageBase;

                // Ensure symbol is generated and set to code type.
                makeUnnamedSymbol(targetAddress, result, true);

                // Check if another pointer exists after this one.
                functionPointer += sizeof(uint32_t);
              }
            }
            else if (opcode == 1137 /* X86::JMP32m */ &&
                     _RVASymbol.count(functionPointer) != 0) {
              // Detect if this is import jump table code. If so, associate it
              // with its respective SharedLibraryAtoms. Detection will fail if
              // the file only contains a single import (would need to aggressively
	      		  // detect based on presence of any single JMP32m instruction)
              if (_importSymbolAtom.count(_RVASymbol[functionPointer]) != 0) {
                if (checkImpThunkStart != -1) {
                  if (numImportThunks == 0) {
                    if (auto ec = makeUnnamedSymbol(checkImpThunkStart, result))
                      return ec;
                    _importSymbolAtom[_RVASymbol[checkImpThunkStart]] =
                      _importSymbolAtom[_RVASymbol[checkImpThunkStartTarget]];
                    // ** TODO mark import as function?
                  }
                  if (auto ec = makeUnnamedSymbol(SectionAddr + Index, result))
                    return ec;
                  _importSymbolAtom[_RVASymbol[SectionAddr + Index]] =
                    _importSymbolAtom[_RVASymbol[functionPointer]];
                  // ** TODO mark import as function?

                  ++numImportThunks;
                }
                else {
                  checkImpThunkStart = SectionAddr + Index;
                  checkImpThunkStartTarget = functionPointer;
                }
              }
            }
          }
          else // Error, uninitialized pointer, or different operand form.
            continue;
        }
        else if (opcode == 1267 /* X86::LEA32r */) {
          auto operand = Inst.getOperand(4).getImm();
          uintptr_t pointer = operand - _PEHeader->ImageBase;
          uintptr_t pointerAddress = SectionAddr + Index + 2;

          if (BaseRelocs.count(SectionAddr + Index) == 0 &&
              BaseRelocs.count(pointerAddress) != 0) {
            // False positives are generated because this instruction's operand
            // is base relocated. Delete them.
            auto iter = _RVASymbol.find(pointer);
            if (iter != _RVASymbol.end())
              deleteSymbol(iter->second, result);
          }
        }
        else
          continue;

        if (targetAddress != -1) {
          // If target is in another section, make sure to mark the section
          // for disassembly in case it is technically a data section.
          if (targetAddress >= End || targetAddress < Start) {
            llvm::object::SectionRef targetSec;
            uint32_t targetSecNum;
            if (auto ec =
                findSectionContaining(targetAddress, targetSec, targetSecNum))
              return ec;
            SecHasCode[targetSec] = true;
          }

          // Ensure the symbol is generated and set to code type.
          makeUnnamedSymbol(targetAddress, result, true);
        }
      }
      else {
        llvm::errs() << "DISASM: warning: invalid instruction encoding at "
                     << llvm::format("%8" PRIx64, SectionAddr + Index) << "\n";
        if (Size == 0)
          Size = 1; // skip illegible bytes
      }
    }
  }

  // Go back over the detected JMP_4 instructions and mark ones which jump into
  // other symbols for needing relative relocations.
  for (auto &J : jumps) {
    auto src = _RVASymbol.lower_bound(J.first),
         dst = _RVASymbol.lower_bound(J.second);
    if (dst != _RVASymbol.end() && src != dst)
      _relativeRelocationRVA.insert(J);
  }

  return std::error_code();
}

/// Add relocation information to an atom based on \p rel. Executables only.
/// \p rel is a relative pointer, and \p atoms are all the atoms defined in
/// the \p section.
std::error_code FileCOFF::addRelativeRelocationReference(
  const uintptr_t rel,
  const uintptr_t target,
  const coff_section *section) {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  uint32_t SectionNumber;
  llvm::object::SectionRef Sec;
  if (auto ec = findSectionContaining(target, Sec, SectionNumber)) return ec;
  const coff_section *sSection = _obj->getCOFFSection(Sec);

  COFFDefinedFileAtom *targetAtom, *atom;
  uint32_t offsetInAtom;
  if (auto ec = findAtomAt(sSection,
    target - sSection->VirtualAddress,
    targetAtom, offsetInAtom))
    return ec;

  if (auto ec = findAtomAt(section, rel - section->VirtualAddress,
    atom, offsetInAtom))
    return ec;
  atom->addReference(llvm::make_unique<SimpleReference>(
    Reference::KindNamespace::COFF, _referenceArch,
    llvm::COFF::IMAGE_REL_I386_REL32, offsetInAtom, targetAtom, 0));
  return std::error_code();
}

/// Add relative relocation information to atoms. Executables only.
std::error_code FileCOFF::addRelativeRelocationReferenceToAtoms() {
  if (_PEHeader == nullptr) return llvm::object::object_error::invalid_file_type;

  // Iterate over the cached RVAs from parsing the disassembly earlier.
  for (auto &rel : _relativeRelocationRVA) {
    uint32_t SectionNumber;
    llvm::object::SectionRef Sec;
    if (auto ec = findSectionContaining(rel.first, Sec, SectionNumber)) return ec;
    const coff_section *section = _obj->getCOFFSection(Sec);

    // Skip if there's no atom for the section. Currently we do not create any
    // atoms for some sections, such as "debug$S", and such sections need to
    // be skipped here too.
    if (_sectionAtoms.find(section) == _sectionAtoms.end()) continue;

    if (auto ec = addRelativeRelocationReference(rel.first, rel.second, section))
      return ec;
  }

  return std::error_code();
}

/// End COFFer extensions
/////////////////////////////

/// Create atoms for the absolute symbols.
void FileCOFF::createAbsoluteAtoms(const SymbolVectorT &symbols,
                                   std::vector<const AbsoluteAtom *> &result) {
  for (llvm::object::COFFSymbolRef sym : symbols) {
    if (sym.getSectionNumber() != llvm::COFF::IMAGE_SYM_ABSOLUTE)
      continue;
    auto *atom = new (_alloc) SimpleAbsoluteAtom(*this, _symbolName[sym],
                                                 getScope(sym), sym.getValue());
    result.push_back(atom);
    _symbolAtom[sym] = atom;
  }
}

/// Create atoms for the undefined symbols. This code is bit complicated
/// because it supports "weak externals" mechanism of COFF. If an undefined
/// symbol (sym1) has auxiliary data, the data contains a symbol table index
/// at which the "second symbol" (sym2) for sym1 exists. If sym1 is resolved,
/// it's linked normally. If not, sym1 is resolved as if it has sym2's
/// name. This relationship between sym1 and sym2 is represented using
/// fallback mechanism of undefined symbol.
std::error_code
FileCOFF::createUndefinedAtoms(const SymbolVectorT &symbols,
                               std::vector<const UndefinedAtom *> &result) {
  std::map<llvm::object::COFFSymbolRef, llvm::object::COFFSymbolRef>
      weakExternal;
  std::set<llvm::object::COFFSymbolRef> fallback;
  for (llvm::object::COFFSymbolRef sym : symbols) {
    if (sym.getSectionNumber() != llvm::COFF::IMAGE_SYM_UNDEFINED)
      continue;
    // Create a mapping from sym1 to sym2, if the undefined symbol has
    // auxiliary data.
    auto iter = _auxSymbol.find(sym);
    if (iter == _auxSymbol.end())
      continue;
    const coff_aux_weak_external *aux =
        reinterpret_cast<const coff_aux_weak_external *>(
            iter->second.getRawPtr());
    ErrorOr<llvm::object::COFFSymbolRef> sym2 = _obj->getSymbol(aux->TagIndex);
    if (std::error_code ec = sym2.getError())
      return ec;
    weakExternal[sym] = *sym2;
    fallback.insert(*sym2);
  }

  // Create atoms for the undefined symbols.
  for (llvm::object::COFFSymbolRef sym : symbols) {
    if (sym.getSectionNumber() != llvm::COFF::IMAGE_SYM_UNDEFINED)
      continue;
    if (fallback.count(sym) > 0)
      continue;

    // If the symbol has sym2, create an undefiend atom for sym2, so that we
    // can pass it as a fallback atom.
    UndefinedAtom *fallback = nullptr;
    auto iter = weakExternal.find(sym);
    if (iter != weakExternal.end()) {
      llvm::object::COFFSymbolRef sym2 = iter->second;
      fallback = new (_alloc) COFFUndefinedAtom(*this, _symbolName[sym2]);
      _symbolAtom[sym2] = fallback;
    }

    // Create an atom for the symbol.
    auto *atom =
        new (_alloc) COFFUndefinedAtom(*this, _symbolName[sym], fallback);
    result.push_back(atom);
    _symbolAtom[sym] = atom;
  }
  return std::error_code();
}

/// Create atoms for the defined symbols. This pass is a bit complicated than
/// the other two, because in order to create the atom for the defined symbol
/// we need to know the adjacent symbols.
std::error_code
FileCOFF::createDefinedSymbols(const SymbolVectorT &symbols,
                               std::vector<const DefinedAtom *> &result) {
  // A defined atom can be merged if its section attribute allows its contents
  // to be merged. In COFF, it's not very easy to get the section attribute
  // for the symbol, so scan all sections in advance and cache the attributes
  // for later use.
  if (std::error_code ec = cacheSectionAttributes())
    return ec;

  // Filter non-defined atoms, and group defined atoms by its section.
  SectionToSymbolsT definedSymbols;
  for (llvm::object::COFFSymbolRef sym : symbols) {
    // A symbol with section number 0 and non-zero value represents a common
    // symbol. The MS COFF spec did not give a definition of what the common
    // symbol is. We should probably follow ELF's definition shown below.
    //
    // - If one object file has a common symbol and another has a definition,
    //   the common symbol is treated as an undefined reference.
    // - If there is no definition for a common symbol, the program linker
    //   acts as though it saw a definition initialized to zero of the
    //   appropriate size.
    // - Two object files may have common symbols of
    //   different sizes, in which case the program linker will use the
    //   largest size.
    //
    // FIXME: We are currently treating the common symbol as a normal
    // mergeable atom. Implement the above semantcis.
    if (sym.getSectionNumber() == llvm::COFF::IMAGE_SYM_UNDEFINED &&
        sym.getValue() > 0) {
      StringRef name = _symbolName[sym];
      uint32_t size = sym.getValue();
      auto *atom = new (_alloc)
          COFFBSSAtom(*this, name, getScope(sym), DefinedAtom::permRW_,
                      DefinedAtom::mergeAsWeakAndAddressUsed, size, getNextOrdinal());

      // Common symbols should be aligned on natural boundaries with the maximum
      // of 32 byte. It's not documented anywhere, but it's what MSVC link.exe
      // seems to be doing.
      atom->setAlignment(std::min((uint64_t)32, llvm::NextPowerOf2(size)));
      result.push_back(atom);
      continue;
    }

    // Skip if it's not for defined atom.
    if (sym.getSectionNumber() == llvm::COFF::IMAGE_SYM_DEBUG ||
        sym.getSectionNumber() == llvm::COFF::IMAGE_SYM_ABSOLUTE ||
        sym.getSectionNumber() == llvm::COFF::IMAGE_SYM_UNDEFINED)
      continue;

    const coff_section *sec;
    if (std::error_code ec = _obj->getSection(sym.getSectionNumber(), sec))
      return ec;
    assert(sec && "SectionIndex > 0, Sec must be non-null!");

    uint8_t sc = sym.getStorageClass();
    if (sc != llvm::COFF::IMAGE_SYM_CLASS_EXTERNAL &&
        sc != llvm::COFF::IMAGE_SYM_CLASS_STATIC &&
        sc != llvm::COFF::IMAGE_SYM_CLASS_FUNCTION &&
        sc != llvm::COFF::IMAGE_SYM_CLASS_LABEL) {
      llvm::errs() << "Unable to create atom for: " << _symbolName[sym] << " ("
                   << static_cast<int>(sc) << ")\n";
      return llvm::object::object_error::parse_failed;
    }

    definedSymbols[sec].push_back(sym);
  }

  // Atomize the defined symbols.
  if (std::error_code ec = AtomizeDefinedSymbols(definedSymbols, result))
    return ec;

  return std::error_code();
}

// Cache the COMDAT attributes, which indicate whether the symbols in the
// section can be merged or not.
std::error_code FileCOFF::cacheSectionAttributes() {
  // The COMDAT section attribute is not an attribute of coff_section, but is
  // stored in the auxiliary symbol for the first symbol referring a COMDAT
  // section. It feels to me that it's unnecessarily complicated, but this is
  // how COFF works.
  for (auto i : _auxSymbol) {
    // Read a section from the file
    llvm::object::COFFSymbolRef sym = i.first;
    if (sym.getSectionNumber() == llvm::COFF::IMAGE_SYM_ABSOLUTE ||
        sym.getSectionNumber() == llvm::COFF::IMAGE_SYM_UNDEFINED)
      continue;

    const coff_section *sec;
    if (std::error_code ec = _obj->getSection(sym.getSectionNumber(), sec))
      return ec;
    const coff_aux_section_definition *aux =
        reinterpret_cast<const coff_aux_section_definition *>(
            i.second.getRawPtr());

    if (sec->Characteristics & llvm::COFF::IMAGE_SCN_LNK_COMDAT) {
      // Read aux symbol data.
      _comdatSections.insert(sec);
      _merge[sec] = getMerge(aux);
    }

    // Handle associative sections.
    if (aux->Selection == llvm::COFF::IMAGE_COMDAT_SELECT_ASSOCIATIVE) {
      const coff_section *parent;
      if (std::error_code ec =
              _obj->getSection(aux->getNumber(sym.isBigObj()), parent))
        return ec;
      _association.insert(std::make_pair(parent, sec));
    }
  }

  // The sections that does not have auxiliary symbol are regular sections, in
  // which symbols are not allowed to be merged.
  for (const auto &section : _obj->sections()) {
    const coff_section *sec = _obj->getCOFFSection(section);
    if (!_merge.count(sec))
      _merge[sec] = DefinedAtom::mergeNo;
  }
  return std::error_code();
}

/// Atomize \p symbols and append the results to \p atoms. The symbols are
/// assumed to have been defined in the \p section.
std::error_code FileCOFF::AtomizeDefinedSymbolsInSection(
    const coff_section *section, SymbolVectorT &symbols,
    std::vector<COFFDefinedFileAtom *> &atoms) {
  // Sort symbols by position.
  std::stable_sort(
      symbols.begin(), symbols.end(),
      [](llvm::object::COFFSymbolRef a, llvm::object::COFFSymbolRef b)
          -> bool { return a.getValue() < b.getValue(); });

  StringRef sectionName;
  if (std::error_code ec = _obj->getSectionName(section, sectionName))
    return ec;

  // BSS section does not have contents. If this is the BSS section, create
  // COFFBSSAtom instead of COFFDefinedAtom.
  if (section->Characteristics & llvm::COFF::IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
    for (auto si = symbols.begin(), se = symbols.end(); si != se; ++si) {
      llvm::object::COFFSymbolRef sym = *si;
      uint32_t size = (si + 1 == se) ? section->SizeOfRawData - sym.getValue()
                                     : si[1].getValue() - sym.getValue();
      auto *atom = new (_alloc) COFFBSSAtom(
          *this, _symbolName[sym], getScope(sym), getPermissions(section),
          DefinedAtom::mergeAsWeakAndAddressUsed, size, getNextOrdinal());
      atoms.push_back(atom);
      _symbolAtom[sym] = atom;
    }
    return std::error_code();
  }

  ArrayRef<uint8_t> secData;
  if (std::error_code ec = _obj->getSectionContents(section, secData))
    return ec;

  // A section with IMAGE_SCN_LNK_{INFO,REMOVE} attribute will never become
  // a part of the output image. That's what the COFF spec says.
  if (section->Characteristics & llvm::COFF::IMAGE_SCN_LNK_INFO ||
      section->Characteristics & llvm::COFF::IMAGE_SCN_LNK_REMOVE)
    return std::error_code();

  // Supporting debug info needs more work than just linking and combining
  // .debug sections. We don't support it yet. Let's discard .debug sections at
  // the very beginning of the process so that we don't spend time on linking
  // blobs that nobody would understand.
  if ((section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_DISCARDABLE) &&
      (sectionName == ".debug" || sectionName.startswith(".debug$"))) {
    return std::error_code();
  }

  DefinedAtom::ContentType type = getContentType(section);
  DefinedAtom::ContentPermissions perms = getPermissions(section);
  uint64_t sectionSize = section->SizeOfRawData;
  bool isComdat = (_comdatSections.count(section) == 1);

  // Create an atom for the entire section.
  if (symbols.empty()) {
    ArrayRef<uint8_t> data(secData.data(), secData.size());
    auto *atom = new (_alloc) COFFDefinedAtom(
        *this, "", sectionName, sectionSize, Atom::scopeTranslationUnit,
        type, isComdat, perms, _merge[section], data, getNextOrdinal());
    atoms.push_back(atom);
    _definedAtomLocations[section].insert(std::make_pair(0, atom));
    return std::error_code();
  }

  // Create an unnamed atom if the first atom isn't at the start of the
  // section.
  if (symbols[0].getValue() != 0) {
    uint64_t size = symbols[0].getValue();
    ArrayRef<uint8_t> data(secData.data(), size);
    auto *atom = new (_alloc) COFFDefinedAtom(
        *this, "", sectionName, sectionSize, Atom::scopeTranslationUnit,
        type, isComdat, perms, _merge[section], data, getNextOrdinal());
    atoms.push_back(atom);
    _definedAtomLocations[section].insert(std::make_pair(0, atom));
  }

  for (auto si = symbols.begin(), se = symbols.end(); si != se; ++si) {
    // ** COFFer modified
    bool valid = si->getStorageClass() != llvm::COFF::IMAGE_SYM_CLASS_LABEL;
    if (!valid)
      continue;
    else {
      uint32_t value = si->getValue();
      if (value < secData.size()) {
        // Create a defined atom.
        const uint8_t *start = secData.data() + value;
        // if this is the last symbol, take up the remaining data.
        const uint8_t *end = (si + 1 == se) ? secData.data() + secData.size()
          : secData.data() + (si + 1)->getValue();
        ArrayRef<uint8_t> data(start, end);
        bool isCodeSym = si->getComplexType() ==
          llvm::COFF::IMAGE_SYM_DTYPE_FUNCTION;
        auto *atom = new (_alloc)COFFDefinedAtom(
          *this, _symbolName[*si], sectionName, sectionSize, getScope(*si),
          (isCodeSym ? DefinedAtom::typeCode : type), isComdat, perms,
          _merge[section], data, getNextOrdinal());
        atoms.push_back(atom);
        _symbolAtom[*si] = atom;
        _definedAtomLocations[section].insert(std::make_pair(value, atom));
      }
      else if (value < section->VirtualSize) {
        // In PECOFF images, uninitialized data is in the region of .*data past
        // raw data size up to virtual size. Create a BSS atom.
        llvm::object::COFFSymbolRef sym = *si;
        uint32_t size = (si + 1 == se) ? section->VirtualSize - sym.getValue()
          : si[1].getValue() - sym.getValue();
        auto *atom = new (_alloc)COFFBSSAtom(
          *this, _symbolName[sym], getScope(sym), getPermissions(section),
          DefinedAtom::mergeAsWeakAndAddressUsed, size, getNextOrdinal());
        atoms.push_back(atom);
        _symbolAtom[sym] = atom;
      }
      else {
        llvm::errs() << "error: unable to create atom for symbol at "
                     << llvm::format("%x", value + section->VirtualAddress)
                     << " (out of section bounds)";
        return llvm::object::object_error::parse_failed;
      }
    }
  }
  return std::error_code();
}

std::error_code FileCOFF::AtomizeDefinedSymbols(
    SectionToSymbolsT &definedSymbols,
    std::vector<const DefinedAtom *> &definedAtoms) {
  // For each section, make atoms for all the symbols defined in the
  // section, and append the atoms to the result objects.
  for (auto &i : definedSymbols) {
    const coff_section *section = i.first;
    SymbolVectorT &symbols = i.second;
    std::vector<COFFDefinedFileAtom *> atoms;
    if (std::error_code ec =
            AtomizeDefinedSymbolsInSection(section, symbols, atoms))
      return ec;

    // Set alignment to the first atom so that the section contents
    // will be aligned as specified by the object section header.
    if (atoms.size() > 0)
      atoms[0]->setAlignment(getAlignment(section));

    // Connect atoms with layout-after edges. It prevents atoms
    // from being GC'ed if there is a reference to one of the atoms
    // in the same layout-after chain. In such case we want to emit
    // all the atoms appeared in the same chain, because the "live"
    // atom may reference other atoms in the same chain.
    if (atoms.size() >= 2)
      for (auto it = atoms.begin(), e = atoms.end(); it + 1 != e; ++it)
        addLayoutEdge(*it, *(it + 1), lld::Reference::kindLayoutAfter);

    for (COFFDefinedFileAtom *atom : atoms) {
      _sectionAtoms[section].push_back(atom);
      definedAtoms.push_back(atom);
    }
  }

  // A COMDAT section with SELECT_ASSOCIATIVE attribute refer to other
  // section. If the referred section is linked to a binary, the
  // referring section needs to be linked too. A typical use case of
  // this attribute is a static initializer; a parent is a comdat BSS
  // section, and a child is a static initializer code for the data.
  //
  // We add referring section contents to the referred section's
  // associate list, so that Resolver takes care of them.
  for (auto i : _association) {
    const coff_section *parent = i.first;
    const coff_section *child = i.second;
    if (_sectionAtoms.count(child)) {
      COFFDefinedFileAtom *p = _sectionAtoms[parent][0];
      p->addAssociate(_sectionAtoms[child][0]);
    }
  }

  return std::error_code();
}

/// Find the atom that is at \p targetAddress in \p section.
std::error_code FileCOFF::findAtomAt(const coff_section *section,
                                     uint32_t targetAddress,
                                     COFFDefinedFileAtom *&result,
                                     uint32_t &offsetInAtom) {
  auto loc = _definedAtomLocations.find(section);
  if (loc == _definedAtomLocations.end())
    return llvm::object::object_error::parse_failed;
  std::multimap<uint32_t, COFFDefinedAtom *> &map = loc->second;

  auto it = map.upper_bound(targetAddress);
  if (it == map.begin())
    return llvm::object::object_error::parse_failed;
  --it;
  uint32_t atomAddress = it->first;
  result = it->second;
  offsetInAtom = targetAddress - atomAddress;
  return std::error_code();
}

/// Find the atom for the symbol that was at the \p index in the symbol
/// table.
std::error_code FileCOFF::getAtomBySymbolIndex(uint32_t index, Atom *&ret) {
  ErrorOr<llvm::object::COFFSymbolRef> symbol = _obj->getSymbol(index);
  if (std::error_code ec = symbol.getError())
    return ec;
  ret = _symbolAtom[*symbol];
  assert(ret);
  return std::error_code();
}

/// Add relocation information to an atom based on \p rel. \p rel is an
/// relocation entry for the \p section, and \p atoms are all the atoms
/// defined in the \p section.
std::error_code FileCOFF::addRelocationReference(
    const coff_relocation *rel, const coff_section *section) {
  // The address of the item which relocation is applied. Section's
  // VirtualAddress needs to be added for historical reasons, but the value
  // is usually just zero, so adding it is usually no-op.
  uint32_t itemAddress = rel->VirtualAddress + section->VirtualAddress;

  Atom *targetAtom = nullptr;
  if (std::error_code ec =
          getAtomBySymbolIndex(rel->SymbolTableIndex, targetAtom))
    return ec;

  COFFDefinedFileAtom *atom;
  uint32_t offsetInAtom;
  if (std::error_code ec = findAtomAt(section, itemAddress, atom, offsetInAtom))
    return ec;
  atom->addReference(llvm::make_unique<SimpleReference>(
      Reference::KindNamespace::COFF, _referenceArch, rel->Type, offsetInAtom,
      targetAtom, 0));
  return std::error_code();
}

// Read section contents.
std::error_code FileCOFF::getSectionContents(StringRef sectionName,
                                             ArrayRef<uint8_t> &result) {
  const coff_section *section = nullptr;
  if (std::error_code ec = findSection(sectionName, section))
    return ec;
  if (!section)
    return std::error_code();
  if (std::error_code ec = _obj->getSectionContents(section, result))
    return ec;
  return std::error_code();
}

AliasAtom *
FileCOFF::createAlias(StringRef name, const DefinedAtom *target, int cnt) {
  AliasAtom *alias = new (_alloc) AliasAtom(*this, name);
  alias->addReference(Reference::KindNamespace::all, Reference::KindArch::all,
                      Reference::kindLayoutAfter, 0, target, 0);
  alias->setMerge(DefinedAtom::mergeAsWeak);
  if (target->contentType() == DefinedAtom::typeCode)
    alias->setDeadStrip(DefinedAtom::deadStripNever);
  alias->setOrdinal(target->ordinal() - cnt);
  return alias;
}

void FileCOFF::createAlternateNameAtoms() {
  std::vector<AliasAtom *> aliases;
  for (const DefinedAtom *atom : defined()) {
    int cnt = 1;
    for (StringRef alias : _ctx.getAlternateNames(atom->name()))
      aliases.push_back(createAlias(alias, atom, cnt++));
  }
  for (AliasAtom *alias : aliases)
    _definedAtoms.push_back(alias);
}

// Interpret the contents of .drectve section. If exists, the section contains
// a string containing command line options. The linker is expected to
// interpret the options as if they were given via the command line.
//
// The section mainly contains /defaultlib (-l in Unix), but can contain any
// options as long as they are valid.
std::error_code
FileCOFF::parseDirectiveSection(StringRef directives) {
  DEBUG(llvm::dbgs() << ".drectve: " << directives << "\n");

  // Split the string into tokens, as the shell would do for argv.
  SmallVector<const char *, 16> tokens;
  tokens.push_back("link"); // argv[0] is the command name. Will be ignored.
  llvm::cl::TokenizeWindowsCommandLine(directives, _stringSaver, tokens);
  tokens.push_back(nullptr);

  // Calls the command line parser to interpret the token string as if they
  // were given via the command line.
  int argc = tokens.size() - 1;
  const char **argv = &tokens[0];
  std::string errorMessage;
  llvm::raw_string_ostream stream(errorMessage);
  PECOFFLinkingContext::ParseDirectives parseDirectives =
    _ctx.getParseDirectives();
  bool parseFailed = !parseDirectives(argc, argv, _ctx, stream);
  stream.flush();
  // Print error message if error.
  if (parseFailed) {
    return make_dynamic_error_code(
      Twine("Failed to parse '") + directives + "'\n"
      + "Reason: " + errorMessage);
  }
  if (!errorMessage.empty()) {
    llvm::errs() << "lld warning: " << errorMessage << "\n";
  }
  return std::error_code();
}

/// Returns the target machine type of the current object file.
std::error_code FileCOFF::getReferenceArch(Reference::KindArch &result) {
  switch (_obj->getMachine()) {
  case llvm::COFF::IMAGE_FILE_MACHINE_I386:
    result = Reference::KindArch::x86;
    return std::error_code();
  case llvm::COFF::IMAGE_FILE_MACHINE_AMD64:
    result = Reference::KindArch::x86_64;
    return std::error_code();
  case llvm::COFF::IMAGE_FILE_MACHINE_ARMNT:
    result = Reference::KindArch::ARM;
    return std::error_code();
  case llvm::COFF::IMAGE_FILE_MACHINE_UNKNOWN:
    result = Reference::KindArch::all;
    return std::error_code();
  }
  llvm::errs() << "Unsupported machine type: 0x"
               << llvm::utohexstr(_obj->getMachine()) << '\n';
  return llvm::object::object_error::parse_failed;
}

/// Add relocation information to atoms.
std::error_code FileCOFF::addRelocationReferenceToAtoms() {
  // Relocation entries are defined for each section.
  for (const auto &sec : _obj->sections()) {
    const coff_section *section = _obj->getCOFFSection(sec);

    // Skip if there's no atom for the section. Currently we do not create any
    // atoms for some sections, such as "debug$S", and such sections need to
    // be skipped here too.
    if (_sectionAtoms.find(section) == _sectionAtoms.end())
      continue;

    for (const auto &reloc : sec.relocations()) {
      const coff_relocation *rel = _obj->getCOFFRelocation(reloc);
      if (auto ec = addRelocationReference(rel, section))
        return ec;
    }
  }
  return std::error_code();
}

// Read .sxdata section if exists. .sxdata is a x86-only section that contains a
// vector of symbol offsets. The symbols pointed by this section are SEH handler
// functions contained in the same object file. The linker needs to construct a
// SEH table and emit it to executable.
//
// On x86, exception handler addresses are in stack, so they are vulnerable to
// stack overflow attack. In order to protect against it, Windows runtime uses
// the SEH table to check if a SEH handler address in stack is a real address of
// a handler created by compiler.
//
// What we want to emit from the linker is a vector of SEH handler VAs, but here
// we have a vector of offsets to the symbol table. So we convert the latter to
// the former.
std::error_code FileCOFF::maybeCreateSXDataAtoms() {
  ArrayRef<uint8_t> sxdata;
  if (std::error_code ec = getSectionContents(".sxdata", sxdata))
    return ec;
  if (sxdata.empty())
    return std::error_code();

  auto *atom = new (_alloc) COFFDefinedAtom(
      *this, "", ".sxdata", 0, Atom::scopeTranslationUnit,
      DefinedAtom::typeData, false /*isComdat*/, DefinedAtom::permR__,
      DefinedAtom::mergeNo, sxdata, getNextOrdinal());

  const ulittle32_t *symbolIndex =
      reinterpret_cast<const ulittle32_t *>(sxdata.data());
  int numSymbols = sxdata.size() / sizeof(uint32_t);

  for (int i = 0; i < numSymbols; ++i) {
    Atom *handlerFunc;
    if (std::error_code ec = getAtomBySymbolIndex(symbolIndex[i], handlerFunc))
      return ec;
    int offsetInAtom = i * sizeof(uint32_t);

    uint16_t rtype;
    switch (_obj->getMachine()) {
    case llvm::COFF::IMAGE_FILE_MACHINE_AMD64:
      rtype = llvm::COFF::IMAGE_REL_AMD64_ADDR32;
      break;
    case llvm::COFF::IMAGE_FILE_MACHINE_I386:
      rtype = llvm::COFF::IMAGE_REL_I386_DIR32;
      break;
    default:
      llvm_unreachable("unsupported machine type");
    }

    atom->addReference(llvm::make_unique<SimpleReference>(
      Reference::KindNamespace::COFF, _referenceArch, rtype, offsetInAtom,
      handlerFunc, 0));
  }

  _definedAtoms.push_back(atom);
  return std::error_code();
}

/// Find a section by name.
std::error_code FileCOFF::findSection(StringRef name,
                                      const coff_section *&result) {
  for (const auto &sec : _obj->sections()) {
    const coff_section *section = _obj->getCOFFSection(sec);
    StringRef sectionName;
    if (auto ec = _obj->getSectionName(section, sectionName))
      return ec;
    if (sectionName == name) {
      result = section;
      return std::error_code();
    }
  }
  // Section was not found, but it's not an error. This method returns
  // an error only when there's a read error.
  return std::error_code();
}

// Convert ArrayRef<uint8_t> to std::string. The array contains a string which
// may not be terminated by NUL.
StringRef FileCOFF::ArrayRefToString(ArrayRef<uint8_t> array) {
  // .drectve sections are encoded in either ASCII or UTF-8 with BOM.
  // The PE/COFF spec allows ANSI (Windows-1252 encoding), but seems
  // it's no longer in use.
  // Skip a UTF-8 byte marker if exists.
  if (array.size() >= 3 && array[0] == 0xEF && array[1] == 0xBB &&
      array[2] == 0xBF) {
    array = array.slice(3);
  }
  if (array.empty())
    return "";
  StringRef s(reinterpret_cast<const char *>(array.data()), array.size());
  s = s.substr(0, s.find_first_of('\0'));
  std::string *contents = new (_alloc) std::string(s.data(), s.size());
  return StringRef(*contents).trim();
}

// getNextOrdinal returns a monotonically increasaing uint64_t number
// starting from 1. There's a large gap between two numbers returned
// from this function, so that you can put other atoms between them.
uint64_t FileCOFF::getNextOrdinal() {
  return _ordinal++ << 32;
}

class COFFObjectReader : public Reader {
public:
  COFFObjectReader(PECOFFLinkingContext &ctx) : _ctx(ctx) {}

  bool canParse(file_magic magic, MemoryBufferRef) const override {
    return magic == llvm::sys::fs::file_magic::coff_object ||
           magic == llvm::sys::fs::file_magic::pecoff_executable; // ** COFFer;
  }

  ErrorOr<std::unique_ptr<File>> loadFile(std::unique_ptr<MemoryBuffer> mb,
                                          const Registry &) const override {
    // Parse the memory buffer as PECOFF file.
    std::unique_ptr<File> ret =
        llvm::make_unique<FileCOFF>(std::move(mb), _ctx);
    return std::move(ret);
  }

private:
  PECOFFLinkingContext &_ctx;
};

using namespace llvm::COFF;

const Registry::KindStrings kindStringsI386[] = {
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_ABSOLUTE),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_DIR16),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_REL16),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_DIR32),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_DIR32NB),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_SEG12),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_SECTION),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_SECREL),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_TOKEN),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_SECREL7),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_I386_REL32),
    LLD_KIND_STRING_END};

const Registry::KindStrings kindStringsAMD64[] = {
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_ABSOLUTE),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_ADDR64),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_ADDR32),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_ADDR32NB),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_REL32),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_REL32_1),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_REL32_2),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_REL32_3),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_REL32_4),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_REL32_5),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_SECTION),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_SECREL),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_SECREL7),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_TOKEN),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_SREL32),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_PAIR),
    LLD_KIND_STRING_ENTRY(IMAGE_REL_AMD64_SSPAN32),
    LLD_KIND_STRING_END};

const Registry::KindStrings kindStringsARMNT[] = {
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_ABSOLUTE),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_ADDR32),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_ADDR32NB),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_BRANCH24),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_BRANCH11),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_TOKEN),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_BLX24),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_BLX11),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_SECTION),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_SECREL),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_MOV32A),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_MOV32T),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_BRANCH20T),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_BRANCH24T),
  LLD_KIND_STRING_ENTRY(IMAGE_REL_ARM_BLX23T),
};

} // end namespace anonymous

namespace lld {

void Registry::addSupportCOFFObjects(PECOFFLinkingContext &ctx) {
  add(std::unique_ptr<Reader>(new COFFObjectReader(ctx)));
  addKindTable(Reference::KindNamespace::COFF, Reference::KindArch::x86,
               kindStringsI386);
  addKindTable(Reference::KindNamespace::COFF, Reference::KindArch::x86_64,
               kindStringsAMD64);
  addKindTable(Reference::KindNamespace::COFF, Reference::KindArch::ARM,
               kindStringsARMNT);
}

}

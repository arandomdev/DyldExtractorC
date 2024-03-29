#include <Converter/Stubs/Arm64Utils.h>
#include <Dyld/Context.h>
#include <Provider/PointerTracker.h>
#include <Utils/Utils.h>
#include <argparse/argparse.hpp>
#include <filesystem>
#include <fmt/core.h>

#include "config.h"

namespace fs = std::filesystem;
using namespace DyldExtractor;

struct ProgramArguments {
  fs::path cache_path;
  uint64_t address;
  bool findAddress;
  bool resolveChain;
};

ProgramArguments parseArgs(int argc, char *argv[]) {
  argparse::ArgumentParser program("dyldex_info", DYLDEXTRACTORC_VERSION);

  program.add_argument("cache_path")
      .help("The path to the shared cache. If there are subcaches, give the "
            "main one (typically without the file extension).");

  program.add_argument("-a", "--address")
      .help(
          "Input an address. Hexadecimal numbers must contains the 0x prefix.")
      .scan<'i', uint64_t>()
      .default_value(0);

  program.add_argument("--find-address")
      .help("Find the image that contains the address.")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("--resolve-chain")
      .help("Resolve a stub chain")
      .default_value(false)
      .implicit_value(true);

  ProgramArguments args;
  try {
    program.parse_args(argc, argv);

    args.cache_path = fs::path(program.get<std::string>("cache_path"));
    args.address = program.get<uint64_t>("--address");
    args.findAddress = program.get<bool>("--find-address");
    args.resolveChain = program.get<bool>("--resolve-chain");

  } catch (const std::runtime_error &err) {
    std::cerr << "Argument parsing error: " << err.what() << std::endl;
    std::exit(1);
  }

  return args;
}

template <class A>
std::string
formatStubFormat(typename Converter::Stubs::Arm64Utils<A>::StubFormat format) {
  switch (format) {
  case Converter::Stubs::Arm64Utils<A>::StubFormat::StubNormal:
    return "StubNormal";
    break;
  case Converter::Stubs::Arm64Utils<A>::StubFormat::StubOptimized:
    return "StubOptimized";
    break;
  case Converter::Stubs::Arm64Utils<A>::StubFormat::AuthStubNormal:
    return "AuthStubNormal";
    break;
  case Converter::Stubs::Arm64Utils<A>::StubFormat::AuthStubOptimized:
    return "AuthStubOptimized";
    break;
  case Converter::Stubs::Arm64Utils<A>::StubFormat::AuthStubResolver:
    return "AuthStubResolver";
    break;
  case Converter::Stubs::Arm64Utils<A>::StubFormat::Resolver:
    return "Resolver";
    break;

  default:
    Utils::unreachable();
  }
}

template <class A> void program(Dyld::Context &dCtx, ProgramArguments &args) {
  if (args.findAddress) {
    bool found = false;
    for (auto imageInfo : dCtx.images) {
      auto mCtx = dCtx.createMachoCtx<true, typename A::P>(imageInfo);
      if (mCtx.containsAddr(args.address)) {
        // Find the specific segment
        for (const auto &seg : mCtx.segments) {
          if (args.address >= seg.command->vmaddr &&
              args.address < seg.command->vmaddr + seg.command->vmsize) {
            found = true;
            auto imagePath =
                (const char *)(dCtx.file + imageInfo->pathFileOffset);
            std::cout << fmt::format("{}: {}", imagePath, seg.command->segname)
                      << std::endl;
            break;
          }
        }
        break;
      }
    }

    if (!found) {
      std::cerr
          << fmt::format(
                 "Unable to find an image that contains the address {:#x}",
                 args.address)
          << std::endl;
    }
  }

  if (args.resolveChain) {
    if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
      Provider::Accelerator<typename A::P> accelerator;
      Provider::PointerTracker<typename A::P> ptrTracker(dCtx);
      Converter::Stubs::Arm64Utils<A> arm64Utils(dCtx, accelerator, ptrTracker);

      auto currentAddr = args.address;
      while (true) {
        auto data = arm64Utils.resolveStub(currentAddr);
        if (!data) {
          break;
        }

        auto [newAddr, format] = *data;
        std::cout << std::format("{}: {:#x} -> {:#x}",
                                 formatStubFormat<A>(format), currentAddr,
                                 newAddr)
                  << std::endl;
        if (currentAddr == newAddr) {
          break;
        } else {
          currentAddr = newAddr;
        }
      }
    } else {
      std::cerr << "Not implemented for architectures other than arm64."
                << std::endl;
    }
  }
}

int main(int argc, char *argv[]) {
  ProgramArguments args = parseArgs(argc, argv);

  try {
    Dyld::Context dCtx(args.cache_path);

    // use dyld's magic to select arch
    if (strcmp(dCtx.header->magic, "dyld_v1  x86_64") == 0)
      program<Utils::Arch::x86_64>(dCtx, args);
    else if (strcmp(dCtx.header->magic, "dyld_v1 x86_64h") == 0)
      program<Utils::Arch::x86_64>(dCtx, args);
    else if (strcmp(dCtx.header->magic, "dyld_v1   armv7") == 0)
      program<Utils::Arch::arm>(dCtx, args);
    else if (strncmp(dCtx.header->magic, "dyld_v1  armv7", 14) == 0)
      program<Utils::Arch::arm>(dCtx, args);
    else if (strcmp(dCtx.header->magic, "dyld_v1   arm64") == 0)
      program<Utils::Arch::arm64>(dCtx, args);
    else if (strcmp(dCtx.header->magic, "dyld_v1  arm64e") == 0)
      program<Utils::Arch::arm64>(dCtx, args);
    else if (strcmp(dCtx.header->magic, "dyld_v1arm64_32") == 0)
      program<Utils::Arch::arm64_32>(dCtx, args);
    else if (strcmp(dCtx.header->magic, "dyld_v1    i386") == 0 ||
             strcmp(dCtx.header->magic, "dyld_v1   armv5") == 0 ||
             strcmp(dCtx.header->magic, "dyld_v1   armv6") == 0) {
      std::cerr << "Unsupported Architecture type.";
      return 1;
    } else {
      std::cerr << "Unrecognized dyld shared cache magic.\n";
      return 1;
    }

  } catch (const std::exception &e) {
    std::cerr << "An error has occurred: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}
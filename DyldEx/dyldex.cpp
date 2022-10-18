#include <filesystem>
#include <fstream>
#include <iostream>

#include <argparse/argparse.hpp>
#include <spdlog/spdlog.h>

#include <Converter/Linkedit/Linkedit.h>
#include <Converter/Objc/Objc.h>
#include <Converter/OffsetOptimizer.h>
#include <Converter/Slide.h>
#include <Converter/Stubs/Stubs.h>
#include <Dyld/Context.h>
#include <Logger/Activity.h>
#include <Macho/Context.h>
#include <Provider/Validator.h>
#include <Utils/ExtractionContext.h>

#include "config.h"

namespace fs = std::filesystem;
using namespace DyldExtractor;

struct ProgramArguments {
  fs::path cache_path;
  bool verbose;
  bool listImages;
  std::optional<std::string> listFilter;
  std::optional<std::string> extractImage;
  std::optional<fs::path> outputPath;
  bool imbedVersion;

  union {
    uint32_t raw;
    struct {
      uint32_t processSlideInfo : 1, optimizeLinkedit : 1, fixStubs : 1,
          fixObjc : 1, generateMetadata : 1, unused : 27;
    };
  } modulesDisabled;
};

ProgramArguments parseArgs(int argc, char *argv[]) {
  argparse::ArgumentParser program("dyldex", DYLDEXTRACTORC_VERSION);

  program.add_argument("cache_path")
      .help("The path to the shared cache. If there are subcaches, give the "
            "main one (typically without the file extension).");

  program.add_argument("-v", "--verbose")
      .help("Enables debug logging messages.")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("-l", "--list-images")
      .help("Lists the images in the shared cache.")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("-f", "--filter").help("Filter images when listing.");

  program.add_argument("-e", "--extract")
      .help("Extract the image. Specify more of the path for conflicts in "
            "image names");

  program.add_argument("-o", "--output")
      .help("The output path for the extracted image. Required for extraction");

  program.add_argument("-s", "--skip-modules")
      .help("Skip certain modules. Most modules depend on each other, so use "
            "with caution. Useful for development. 1=processSlideInfo, "
            "2=optimizeLinkedit, 4=fixStubs, 8=fixObjc, 16=generateMetadata")
      .scan<'d', int>()
      .default_value(0);

  program.add_argument("--imbed-version")
      .help("Imbed this tool's version number into the mach_header_64's "
            "reserved field. Only supports 64 bit images.")
      .default_value(false)
      .implicit_value(true);

  ProgramArguments args;
  try {
    program.parse_args(argc, argv);

    args.cache_path = fs::path(program.get<std::string>("cache_path"));
    args.verbose = program.get<bool>("--verbose");
    args.listImages = program.get<bool>("--list-images");
    args.listFilter = program.present<std::string>("--filter");
    args.extractImage = program.present<std::string>("--extract");
    args.outputPath = program.present<std::string>("--output");
    args.modulesDisabled.raw = program.get<int>("--skip-modules");
    args.imbedVersion = program.get<bool>("--imbed-version");
  } catch (const std::runtime_error &err) {
    std::cerr << "Argument parsing error: " << err.what() << std::endl;
    std::exit(1);
  }

  if (args.extractImage && !args.outputPath) {
    std::cerr << "Output path is required for extraction" << std::endl;
    std::exit(1);
  }

  return args;
}

/// Retrieve images in the cache, with an optional filter.
std::vector<std::tuple<int, std::string>>
getImages(Dyld::Context &dCtx, std::optional<std::string> filter) {
  std::vector<std::tuple<int, std::string>> images;
  images.reserve(dCtx.images.size());

  for (int i = 0; i < dCtx.images.size(); i++) {
    auto imagePath =
        std::string((const char *)dCtx.file + dCtx.images[i]->pathFileOffset);

    if (filter) {
      auto it = std::search(imagePath.begin(), imagePath.end(), filter->begin(),
                            filter->end(), [](char ch1, char ch2) {
                              return std::tolower(ch1) == std::tolower(ch2);
                            });
      if (it == imagePath.end()) {
        continue;
      }
    }

    images.emplace_back(i, imagePath);
  }

  return images;
}

template <class A>
void extractImage(Dyld::Context &dCtx, ProgramArguments args) {
  using P = A::P;

  // Get the image info of the extraction target
  assert(args.extractImage != std::nullopt);

  auto extractionTargetFilter = *args.extractImage;
  auto possibleTargets = getImages(dCtx, args.extractImage);
  if (possibleTargets.size() == 0) {
    std::cerr << fmt::format("Unable to find image '{}'",
                             extractionTargetFilter)
              << std::endl;
    return;
  }

  auto &[imageIndex, imagePath] = possibleTargets[0];
  auto imageInfo = dCtx.images[imageIndex];
  std::cout << fmt::format("Extracting '{}'", imagePath) << std::endl;

  auto mCtx = dCtx.createMachoCtx<false, P>(imageInfo);

  // validate
  try {
    Provider::Validator<P>(mCtx).validate();
  } catch (const std::exception &e) {
    std::cout << std::format("Validation Error: {}", e.what());
    return;
  }

  // Setup context and extract
  Logger::Activity activity("DyldEx", std::cout, true);
  activity.logger->set_pattern("[%T:%e %-8l %s:%#] %v");
  if (args.verbose) {
    activity.logger->set_level(spdlog::level::trace);
  } else {
    activity.logger->set_level(spdlog::level::info);
  }
  activity.update("DyldEx", "Starting up");

  Provider::Accelerator<P> accelerator;
  Utils::ExtractionContext<A> eCtx(dCtx, mCtx, activity, accelerator);

  // Process
  if (!args.modulesDisabled.processSlideInfo) {
    Converter::processSlideInfo(eCtx);
  }
  if (!args.modulesDisabled.optimizeLinkedit) {
    Converter::optimizeLinkedit(eCtx);
  }
  if (!args.modulesDisabled.fixStubs) {
    Converter::fixStubs(eCtx);
  }
  if (!args.modulesDisabled.fixObjc) {
    Converter::fixObjc(eCtx);
  }
  if (!args.modulesDisabled.generateMetadata) {
    Converter::generateMetadata(eCtx);
  }

  if (args.imbedVersion) {
    if constexpr (!std::is_same_v<P, Utils::Arch::Pointer64>) {
      SPDLOG_LOGGER_ERROR(
          activity.logger,
          "Unable to imbed version info in a non 64 bit image.");
    } else {
      mCtx.header->reserved = DYLDEXTRACTORC_VERSION_DATA;
    }
  }
  auto writeProcedures = Converter::optimizeOffsets(eCtx);

  // Write
  fs::create_directories(args.outputPath->parent_path());
  std::ofstream outFile(*args.outputPath, std::ios_base::binary);
  if (!outFile.good()) {
    SPDLOG_LOGGER_ERROR(activity.logger, "Unable to open output file.");
    return;
  }

  for (auto procedure : writeProcedures) {
    outFile.seekp(procedure.writeOffset);
    outFile.write((const char *)procedure.source, procedure.size);
  }
  outFile.close();

  activity.update("DyldEx", "Done");
  activity.stopActivity();
}

int main(int argc, char *argv[]) {
  ProgramArguments args = parseArgs(argc, argv);

  try {
    Dyld::Context dCtx(args.cache_path);

    if (args.listImages) {
      for (auto &[i, path] : getImages(dCtx, args.listFilter)) {
        std::cout << path << std::endl;
      }
      return 0;
    } else if (args.extractImage) {
      // use dyld's magic to select arch
      if (strcmp(dCtx.header->magic, "dyld_v1  x86_64") == 0)
        extractImage<Utils::Arch::x86_64>(dCtx, args);
      else if (strcmp(dCtx.header->magic, "dyld_v1 x86_64h") == 0)
        extractImage<Utils::Arch::x86_64>(dCtx, args);
      else if (strcmp(dCtx.header->magic, "dyld_v1   armv7") == 0)
        extractImage<Utils::Arch::arm>(dCtx, args);
      else if (strncmp(dCtx.header->magic, "dyld_v1  armv7", 14) == 0)
        extractImage<Utils::Arch::arm>(dCtx, args);
      else if (strcmp(dCtx.header->magic, "dyld_v1   arm64") == 0)
        extractImage<Utils::Arch::arm64>(dCtx, args);
      else if (strcmp(dCtx.header->magic, "dyld_v1  arm64e") == 0)
        extractImage<Utils::Arch::arm64>(dCtx, args);
      else if (strcmp(dCtx.header->magic, "dyld_v1arm64_32") == 0)
        extractImage<Utils::Arch::arm64_32>(dCtx, args);
      else if (strcmp(dCtx.header->magic, "dyld_v1    i386") == 0 ||
               strcmp(dCtx.header->magic, "dyld_v1   armv5") == 0 ||
               strcmp(dCtx.header->magic, "dyld_v1   armv6") == 0) {
        std::cerr << "Unsupported Architecture type.";
        return 1;
      } else {
        std::cerr << "Unrecognized dyld shared cache magic.\n";
        return 1;
      }
    }
  } catch (const std::exception &e) {
    std::cerr << "An error has occurred: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}
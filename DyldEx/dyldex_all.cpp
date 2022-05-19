#include <filesystem>
#include <fstream>
#include <iostream>

#include <argparse/argparse.hpp>
#include <spdlog/spdlog.h>

#include <Converter/LinkeditOptimizer.h>
#include <Converter/OffsetOptimizer.h>
#include <Converter/Slide.h>
#include <Converter/Stubs.h>
#include <Dyld/Context.h>
#include <Logger/ActivityLogger.h>
#include <Macho/Context.h>
#include <Utils/Accelerator.h>
#include <Utils/ExtractionContext.h>

namespace fs = std::filesystem;

struct ProgramArguments {
    fs::path cache_path;
    std::optional<fs::path> outputDir;
    bool verbose;
    bool disableOutput;

    union {
        uint32_t _raw;
        struct {
            uint32_t processSlideInfo : 1, optimizeLinkedit : 1, fixStubs : 1,
                unused : 29;
        };
    } modulesDisabled;
};

ProgramArguments parseArgs(int argc, char *argv[]) {
    argparse::ArgumentParser program("dyldex_all");

    // TODO: specify main cache
    program.add_argument("cache_path")
        .help("The path to the shared cache. If there are subcaches, give the "
              "directory.");

    program.add_argument("-o", "--output-dir")
        .help("The output directory for the extracted images. Required for "
              "extraction");

    program.add_argument("-V", "--verbose")
        .help("Enables debug logging messages.")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-d", "--disable-output")
        .help("Disables writing output. Useful for development.")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-s", "--skip-modules")
        .help("Skip certain modules. Most modules depend on each other, so use "
              "with caution. Useful for development. 1=processSlideInfo, "
              "2=optimizeLinkedit, 4=fixStubs")
        .scan<'d', int>()
        .default_value(0);

    ProgramArguments args;
    try {
        program.parse_args(argc, argv);

        args.cache_path = fs::path(program.get<std::string>("cache_path"));
        args.outputDir = program.present<std::string>("--output-dir");
        args.verbose = program.get<bool>("--verbose");
        args.disableOutput = program.get<bool>("--disable-output");
        args.modulesDisabled._raw = program.get<int>("--skip-modules");

    } catch (const std::runtime_error &err) {
        std::cerr << "Argument parsing error: " << err.what() << std::endl;
        std::exit(1);
    }

    if (!args.disableOutput && !args.outputDir) {
        std::cerr << "Output directory is required for extraction" << std::endl;
        std::exit(1);
    }

    return args;
}

template <class A>
void runImage(Dyld::Context &dCtx,
              Utils::Accelerator<typename A::P> *accelerator,
              const dyld_cache_image_info *imageInfo,
              const std::string imagePath, const std::string imageName,
              const ProgramArguments &args, std::ostream &logStream) {
    // Setup context
    ActivityLogger activity("DyldEx_" + imageName, logStream, false);
    activity.logger->set_pattern("[%-8l %s:%#] %v");
    if (args.verbose) {
        activity.logger->set_level(spdlog::level::trace);
    } else {
        activity.logger->set_level(spdlog::level::info);
    }

    logStream << std::format("Running {}", imageName) << std::endl;

    auto mCtx = dCtx.createMachoCtx<false, A::P>(imageInfo);
    Utils::ExtractionContext<A::P> eCtx(dCtx, mCtx, &activity);
    eCtx.accelerator = accelerator;

    if (!args.modulesDisabled.processSlideInfo) {
        Converter::processSlideInfo(eCtx);
    }
    if (!args.modulesDisabled.optimizeLinkedit) {
        Converter::optimizeLinkedit(eCtx);
    }
    if (!args.modulesDisabled.fixStubs) {
        Converter::fixStubs<A>(eCtx);
    }

    if (!args.disableOutput) {
        auto writeProcedures = Converter::optimizeOffsets(eCtx);

        auto outputPath =
            *args.outputDir / imagePath.substr(1); // remove leading /
        fs::create_directories(outputPath.parent_path());
        std::ofstream outFile(outputPath, std::ios_base::binary);
        if (!outFile.good()) {
            SPDLOG_LOGGER_ERROR(activity.logger, "Unable to open output file.");
            return;
        }

        for (auto procedure : writeProcedures) {
            outFile.seekp(procedure.writeOffset);
            outFile.write((const char *)procedure.source, procedure.size);
        }
        outFile.close();
    }

    logStream << std::endl;
}

template <class A>
void runAllImages(Dyld::Context &dCtx, ProgramArguments &args) {
    ActivityLogger activity("DyldEx_All", std::cout, true);
    activity.logger->set_pattern("[%T:%e %-8l %s:%#] %v");
    if (args.verbose) {
        activity.logger->set_level(spdlog::level::trace);
    } else {
        activity.logger->set_level(spdlog::level::info);
    }
    activity.update("DyldEx All", "Starting up");

    Utils::Accelerator<typename A::P> accelerator;

    const auto imageCount = dCtx.images.size();
    for (int i = 0; i < imageCount; i++) {
        const auto imageInfo = dCtx.images[i];

        std::string imagePath((char *)(dCtx.file + imageInfo->pathFileOffset));
        std::string imageName = imagePath.substr(imagePath.rfind("/") + 1);

        activity.update(std::nullopt, std::format("[{:4}/{}] {}", i + 1,
                                                  imageCount, imageName));

        runImage<A>(dCtx, &accelerator, imageInfo, imagePath, imageName, args,
                    activity.loggerStream());
    }
}

int main(int argc, char *argv[]) {
    ProgramArguments args = parseArgs(argc, argv);

    try {
        Dyld::Context dCtx(args.cache_path);

        // use dyld's magic to select arch
        if (strcmp(dCtx.header->magic, "dyld_v1  x86_64") == 0)
            runAllImages<Utils::Arch::x86_64>(dCtx, args);
        else if (strcmp(dCtx.header->magic, "dyld_v1 x86_64h") == 0)
            runAllImages<Utils::Arch::x86_64>(dCtx, args);
        else if (strcmp(dCtx.header->magic, "dyld_v1   armv7") == 0)
            runAllImages<Utils::Arch::arm>(dCtx, args);
        else if (strncmp(dCtx.header->magic, "dyld_v1  armv7", 14) == 0)
            runAllImages<Utils::Arch::arm>(dCtx, args);
        else if (strcmp(dCtx.header->magic, "dyld_v1   arm64") == 0)
            runAllImages<Utils::Arch::arm64>(dCtx, args);
        else if (strcmp(dCtx.header->magic, "dyld_v1  arm64e") == 0)
            runAllImages<Utils::Arch::arm64>(dCtx, args);
        else if (strcmp(dCtx.header->magic, "dyld_v1arm64_32") == 0)
            runAllImages<Utils::Arch::arm64_32>(dCtx, args);
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
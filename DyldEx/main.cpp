#include <argparse/argparse.hpp>
#include <chrono>
#include <dyld/dyld_cache_format.h>
#include <filesystem>
#include <iostream>
#include <thread>

#include <Dyld/Context.h>
#include <Logger/ActivityLogger.h>
#include <Macho/Context.h>
#include <Utils/ExtractionContext.h>

namespace fs = std::filesystem;

struct ProgramArguments {
    fs::path cache_path;
    bool verbose;
    bool listImages;
    std::optional<std::string> listFilter;
    std::optional<std::string> extractImage;
    std::optional<fs::path> outputPath;
};

ProgramArguments parseArgs(int argc, char *argv[]) {
    argparse::ArgumentParser program("DyldEx");

    // TODO: specify main cache
    program.add_argument("cache_path")
        .help("The path to the shared cache. If there are subcaches, give the "
              "directory.");

    program.add_argument("-V", "--verbose")
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
        .help(
            "The output path for the extracted image. Required for extraction");

    ProgramArguments args;
    try {
        program.parse_args(argc, argv);

        args.cache_path = fs::path(program.get<std::string>("cache_path"));
        args.verbose = program.get<bool>("--verbose");
        args.listImages = program.get<bool>("--list-images");
        args.listFilter = program.present<std::string>("--filter");
        args.extractImage = program.present<std::string>("--extract");
        args.outputPath = program.present<std::string>("--output");
    } catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::exit(1);
    }

    return args;
}

/// Retrieve images in the cache, with an optional filter.
std::vector<std::tuple<int, std::string>>
getImages(Dyld::Context *dyldCtx, std::optional<std::string> filter) {
    std::vector<std::tuple<int, std::string>> images;
    images.reserve(dyldCtx->images.size());

    for (int i = 0; i < dyldCtx->images.size(); i++) {
        auto imagePath =
            std::string(dyldCtx->file + dyldCtx->images[i]->pathFileOffset);

        if (filter) {
            auto it =
                std::search(imagePath.begin(), imagePath.end(), filter->begin(),
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

void extractImage(Dyld::Context *dyldCtx, ProgramArguments args) {
    // Get the image info of the extraction target
    assert(args.extractImage != std::nullopt);

    auto extractionTargetFilter = *args.extractImage;
    auto possibleTargets = getImages(dyldCtx, args.extractImage);
    if (possibleTargets.size() == 0) {
        std::cerr << "Unable to find image '" + extractionTargetFilter + "'"
                  << std::endl;
        return;
    }

    auto &[imageIndex, imagePath] = possibleTargets[0];
    auto imageInfo = dyldCtx->images[imageIndex];
    std::cout << "Extracting '" + imagePath + "'" << std::endl;

    // Setup context
    ActivityLogger activity("DyldEx", std::cout, true);
    activity.logger->set_pattern("[%T:%e] [%l] %v");
    if (args.verbose) {
        activity.logger->set_level(spdlog::level::debug);
    } else {
        activity.logger->set_level(spdlog::level::info);
    }

    auto machoCtx = dyldCtx->createMachoCtx<false>(imageInfo);
    Utils::ExtractionContext extractionCtx(dyldCtx, &machoCtx, &activity,
                                           activity.logger);
}

int main(int argc, char *argv[]) {
    ProgramArguments args = parseArgs(argc, argv);

    try {
        Dyld::Context dyldCtx(args.cache_path);

        if (args.listImages) {
            for (auto &[i, path] : getImages(&dyldCtx, args.listFilter)) {
                std::cout << path << std::endl;
            }
            return 0;
        } else if (args.extractImage) {
            extractImage(&dyldCtx, args);
        }
    } catch (const std::exception &e) {
        std::cerr << "An error has occurred: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
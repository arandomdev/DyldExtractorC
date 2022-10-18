#include <argparse/argparse.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/sync/interprocess_condition.hpp>
#include <boost/process.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <thread>

#include <Converter/Linkedit/Linkedit.h>
#include <Converter/Objc/Objc.h>
#include <Converter/OffsetOptimizer.h>
#include <Converter/Slide.h>
#include <Converter/Stubs/Stubs.h>
#include <Dyld/Context.h>
#include <Provider/Accelerator.h>
#include <Provider/Validator.h>
#include <Utils/ExtractionContext.h>

#include "config.h"

namespace bi = boost::interprocess;
namespace bp = boost::process;
namespace fs = std::filesystem;
using namespace DyldExtractor;

#pragma region Arguments
struct ProgramArguments {
  std::vector<std::string> rawArguments;

  fs::path programPath;
  fs::path cachePath;
  std::optional<fs::path> outputDir;
  bool disableOutput;
  bool verbose;
  bool quiet;
  bool onlyValidate;
  unsigned int jobs;
  bool imbedVersion;

  union {
    uint32_t raw;
    struct {
      uint32_t processSlideInfo : 1, optimizeLinkedit : 1, fixStubs : 1,
          fixObjc : 1, generateMetadata : 1, unused : 27;
    };
  } modulesDisabled;

  struct ClientSpecification {
    enum class Arch { x86_64, arm, arm64, arm64_32 };

    bool inClientMode = false;
    std::string clientID;
    Arch arch;

    unsigned int start;
    unsigned int end;
    unsigned int skip;
  } clientSpec;
};

ProgramArguments parseArgs(int argc, char const *argv[]) {
  argparse::ArgumentParser program("dyldex_all_multiprocess",
                                   DYLDEXTRACTORC_VERSION);

  program.add_argument("cache_path")
      .help("The path to the shared cache. If there are subcaches, give the "
            "main one (typically without the file extension).");

  program.add_argument("-o", "--output-dir")
      .help("The output directory for the extracted images. Required for "
            "extraction");

  program.add_argument("-d", "--disable-output")
      .help("Disables writing output. Useful for development.")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("-v", "--verbose")
      .help("Enables debug logging messages.")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("-q", "--quiet")
      .help("Omits the processed images messages unless there are logs.")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("--only-validate")
      .help("Only validate images.")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("-j", "--jobs")
      .help("The number of parallel clients to run.")
      .scan<'d', unsigned int>()
      .default_value(std::thread::hardware_concurrency());

  program.add_argument("-s", "--skip-modules")
      .help("Skip certain modules. Most modules depend on each other, so use "
            "with caution. Useful for development. 1=processSlideInfo, "
            "2=optimizeLinkedit, 4=fixStubs, 8=fixObjc, 16=generateMetadata")
      .scan<'d', int>()
      .default_value(0);

  program.add_argument("--client-spec")
      .help("Do not use. This is used for multiprocess support.")
      .nargs(5);

  program.add_argument("--imbed-version")
      .help("Imbed this tool's version number into the mach_header_64's "
            "reserved field. Only supports 64 bit images.")
      .default_value(false)
      .implicit_value(true);

  ProgramArguments args;
  std::copy(argv + 1, argv + argc, std::back_inserter(args.rawArguments));

  try {
    program.parse_args(argc, argv);

    args.programPath = fs::path(argv[0]);
    args.cachePath = fs::path(program.get<std::string>("cache_path"));
    args.outputDir = program.present<std::string>("--output-dir");
    args.disableOutput = program.get<bool>("--disable-output");
    args.verbose = program.get<bool>("--verbose");
    args.quiet = program.get<bool>("--quiet");
    args.onlyValidate = program.get<bool>("--only-validate");
    args.jobs = program.get<unsigned int>("--jobs");
    args.modulesDisabled.raw = program.get<int>("--skip-modules");
    args.imbedVersion = program.get<bool>("--imbed-version");

    if (auto clientSpec =
            program.present<std::vector<std::string>>("--client-spec")) {
      // Format: ClientID, Arch, start, end, skip
      args.clientSpec.inClientMode = true;
      args.clientSpec.clientID = clientSpec->at(0);
      args.clientSpec.arch =
          static_cast<ProgramArguments::ClientSpecification::Arch>(
              std::stoi(clientSpec->at(1)));
      args.clientSpec.start = std::stoul(clientSpec->at(2));
      args.clientSpec.end = std::stoul(clientSpec->at(3));
      args.clientSpec.skip = std::stoul(clientSpec->at(4));
    };
  } catch (const std::runtime_error &e) {
    std::cerr << "Error while parsing arguments: " << e.what() << std::endl;
    std::exit(1);
  }

  return args;
}
#pragma endregion Arguments

#pragma region MessageQueue
#define SHARED_MESSAGE_QUEUE_NAME "SharedMessageQueue"

// A local copy of the shared message
struct LocalMessage {
  // The client id sending the message
  std::string clientID;
  // The processed image that corresponds to the logs
  std::string currentImage;
  // Logs for the process image
  std::string logs;
  // The image to process next
  std::string nextImage;
};

struct MessageQueue {
  using SharedString = typename bi::basic_string<
      char, std::char_traits<char>,
      bi::allocator<char, bi::managed_shared_memory::segment_manager>>;

  MessageQueue(bi::managed_shared_memory::segment_manager *segManager)
      : queueFull(false), message(segManager) {}

  // Mutex to protect access to the queue
  bi::interprocess_mutex mutex;
  // Condition for when the queue is emptied.
  bi::interprocess_condition queueEmptied;
  // Condition for when the queue is filled;
  bi::interprocess_condition queueFilled;
  // Condition for when the message in the queue is handled;
  bi::interprocess_condition messageAck;

  bool queueFull;

  struct Message {
    Message(bi::managed_shared_memory::segment_manager *segManager)
        : clientID(segManager), currentImage(segManager), logs(segManager),
          nextImage(segManager) {}

    Message &operator=(const LocalMessage &other) {
      this->clientID = other.clientID.c_str();
      this->currentImage = other.currentImage.c_str();
      this->logs = other.logs.c_str();
      this->nextImage = other.nextImage.c_str();
      return *this;
    }

    operator LocalMessage() {
      LocalMessage m;
      m.clientID = std::string(clientID.begin(), clientID.end());
      m.currentImage = std::string(currentImage.begin(), currentImage.end());
      m.logs = std::string(logs.begin(), logs.end());
      m.nextImage = std::string(nextImage.begin(), nextImage.end());
      return m;
    }

    // The client id sending the message
    SharedString clientID;
    // The processed image that corresponds to the logs
    SharedString currentImage;
    // Logs for the process image
    SharedString logs;
    // The image to process next
    SharedString nextImage;

  } message;
};

/// Send a message through message queue
void sendMessage(MessageQueue *messageQueue, LocalMessage message) {
  bi::scoped_lock<bi::interprocess_mutex> lock(messageQueue->mutex);
  while (messageQueue->queueFull) {
    messageQueue->queueEmptied.wait(lock);
  }

  messageQueue->message = message;
  messageQueue->queueFull = true;
  messageQueue->queueFilled.notify_one();
}

/// Receive a message though the message queue
std::optional<LocalMessage> receiveMessage(MessageQueue *messageQueue,
                                           std::chrono::milliseconds timeout) {
  bi::scoped_lock<bi::interprocess_mutex> lock(messageQueue->mutex);
  while (!messageQueue->queueFull) {
    auto stat = messageQueue->queueFilled.wait_for(lock, timeout);
    if (stat == bi::cv_status::timeout) {
      return std::nullopt;
    }
  }

  LocalMessage message = messageQueue->message;
  messageQueue->queueFull = false;
  messageQueue->queueEmptied.notify_one();

  return message;
}
#pragma endregion MessageQueue

#pragma region Server
#define SHARED_MEMORY_NAME "dyldex_all_multiprocess"

static volatile sig_atomic_t interrupted = 0;
void sigintHandler(int signum) { interrupted = 1; }

struct ClientProcess {
  bp::child process;

  // The name of the next image to be process
  std::string nextImage;
};

/// Default server that uses multiple processes
template <class A> int server(ProgramArguments &args, Dyld::Context &dCtx) {
  signal(SIGINT, sigintHandler);

  // Create message queue
  struct SharedMemoryRemover {
    SharedMemoryRemover() {
      bi::shared_memory_object::remove(SHARED_MEMORY_NAME);
    }
    ~SharedMemoryRemover() {
      bi::shared_memory_object::remove(SHARED_MEMORY_NAME);
    }
  } sharedMemoryRemover;

  bi::managed_shared_memory sharedMemory(bi::create_only, SHARED_MEMORY_NAME,
                                         65536);
  auto messageQueue = sharedMemory.construct<MessageQueue>(
      SHARED_MESSAGE_QUEUE_NAME)(sharedMemory.get_segment_manager());

  // Server setup
  Logger::Activity activity("dyldex_all_multiprocess", std::cout, true);
  activity.logger->set_pattern("[%T:%e %-8l %s:%#] %v");
  if (args.verbose) {
    activity.logger->set_level(spdlog::level::trace);
  } else {
    activity.logger->set_level(spdlog::level::info);
  }
  activity.update("DyldEx All", "Starting up");

  auto &loggerStream = activity.getLoggerStream();
  std::ostringstream summaryLog;
  int imagesProcessed = 0;
  const int totalImages = (int)dCtx.images.size();

  // Launch clients
  std::vector<std::string> clientArgsBase = args.rawArguments;

  std::string clientArch;
  if constexpr (std::is_same_v<A, Utils::Arch::x86_64>)
    clientArch = std::to_string(
        static_cast<int>(ProgramArguments::ClientSpecification::Arch::x86_64));
  else if constexpr (std::is_same_v<A, Utils::Arch::arm>)
    clientArch = std::to_string(
        static_cast<int>(ProgramArguments::ClientSpecification::Arch::arm));
  else if constexpr (std::is_same_v<A, Utils::Arch::arm64>)
    clientArch = std::to_string(
        static_cast<int>(ProgramArguments::ClientSpecification::Arch::arm64));
  else if constexpr (std::is_same_v<A, Utils::Arch::arm64_32>)
    clientArch = std::to_string(static_cast<int>(
        ProgramArguments::ClientSpecification::Arch::arm64_32));
  else
    return 1;

  bp::group clientGroup;
  std::map<std::string, ClientProcess> clients;
  for (unsigned int i = 0; i < args.jobs; i++) {
    std::string clientID = std::to_string(i);

    auto clientArgs = clientArgsBase;
    clientArgs.emplace_back("--client-spec");
    clientArgs.push_back(clientID);
    clientArgs.push_back(clientArch);
    clientArgs.push_back(std::to_string(i));
    clientArgs.push_back(std::to_string(dCtx.images.size()));
    clientArgs.push_back(std::to_string(args.jobs));

    clients[clientID] = {
        bp::child(args.programPath.string(), bp::args(clientArgs), clientGroup),
        ""};
  }

  // Server loop
  bool clientFailure = false;
  while (true) {
    // Check signal
    if (interrupted) {
      loggerStream << "Stopping all clients" << std::endl;
      break;
    }

    bool stop = false;
    for (auto &[clientID, clientProc] : clients) {
      if (!clientProc.process.running()) {
        clientProc.process.wait();

        auto exitCode = clientProc.process.exit_code();
        if (exitCode == 0 || exitCode == 259) {
          // Client finished its work
          clients.erase(clientID);
        } else {
          loggerStream
              << fmt::format("Client {} has unexpectedly ended with exit code: "
                             "{} while processing {}. Stopping all clients.",
                             clientID, exitCode, clients[clientID].nextImage)
              << std::endl;

          clientFailure = true;
          stop = true;
        }
        break;
      }
    }
    if (stop) {
      break;
    }

    // check message queue
    if (auto message =
            receiveMessage(messageQueue, std::chrono::milliseconds(100))) {
      if (message->currentImage.length()) {
        // update UI
        imagesProcessed++;
        activity.update(std::nullopt,
                        fmt::format("[{:4}/{}]", imagesProcessed, totalImages));

        if (!args.quiet || message->logs.length()) {
          loggerStream << fmt::format("Processed {}\n{}", message->currentImage,
                                      message->logs)
                       << std::endl;
        }

        // Update summary if needed
        if (message->logs.length()) {
          summaryLog << fmt::format("* {}\n{}", message->currentImage,
                                    message->logs)
                     << std::endl;
        }
      }

      clients[message->clientID].nextImage = message->nextImage;
    } else {
      // Make sure that it didn't timeout because there are not any
      // clients
      if (!clients.size()) {
        loggerStream << "All clients have stopped, but there were still images "
                        "left to be process. Stopping."
                     << std::endl;
        break;
      }
    }

    if (imagesProcessed == totalImages) {
      break;
    }
  }

  // stop all clients
  clientGroup.terminate();
  clientGroup.wait();
  for (auto &[clientID, clientProc] : clients) {
    clientProc.process.wait();
  }

  // Write summary
  activity.update(std::nullopt, "Done");
  activity.stopActivity();

  if (auto logs = summaryLog.str(); logs.length()) {
    loggerStream << fmt::format("\n==== Summary ====\n{}=================",
                                logs)
                 << std::endl;
  }

  if (clientFailure) {
    return 1;
  } else {
    return 0;
  }
}
#pragma endregion Server

#pragma region Client
std::pair<std::string, std::string>
getImageName(Dyld::Context &dCtx, const dyld_cache_image_info *image) {
  std::string imagePath((char *)(dCtx.file + image->pathFileOffset));
  std::string imageName = imagePath.substr(imagePath.rfind("/") + 1);
  return std::make_pair(imagePath, imageName);
}

template <class A>
std::ostringstream
processImage(ProgramArguments &args, Dyld::Context &dCtx,
             Provider::Accelerator<typename A::P> &accelerator,
             const dyld_cache_image_info *imageInfo, std::string imagePath,
             std::string imageName) {
  using P = A::P;

  // Setup context
  std::ostringstream loggerStream;
  Logger::Activity activity("dyldex_all_multiprocess_" + imageName,
                            loggerStream, false);
  activity.logger->set_pattern("[%-8l %s:%#] %v");
  if (args.verbose) {
    activity.logger->set_level(spdlog::level::trace);
  } else {
    activity.logger->set_level(spdlog::level::info);
  }

  auto mCtx = dCtx.createMachoCtx<false, P>(imageInfo);

  // Validate
  try {
    Provider::Validator<P>(mCtx).validate();
  } catch (const std::exception &e) {
    SPDLOG_LOGGER_ERROR(activity.logger, "Validation Error: {}", e.what());
    return loggerStream;
  }

  if (args.onlyValidate) {
    return loggerStream;
  }

  Utils::ExtractionContext<A> eCtx(dCtx, mCtx, activity, accelerator);

  // Process image
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

  if (!args.disableOutput) {
    auto writeProcedures = Converter::optimizeOffsets(eCtx);

    auto outputPath = *args.outputDir / imagePath.substr(1); // remove leading /
    fs::create_directories(outputPath.parent_path());
    std::ofstream outFile(outputPath, std::ios_base::binary);
    if (outFile.good()) {
      for (auto procedure : writeProcedures) {
        outFile.seekp(procedure.writeOffset);
        outFile.write((const char *)procedure.source, procedure.size);
      }
      outFile.close();
    } else {
      SPDLOG_LOGGER_ERROR(activity.logger, "Unable to open output file.");
    }
  }

  return loggerStream;
}

template <class A> int client(ProgramArguments &args) {
  using P = A::P;

  // Get shared message queue
  bi::managed_shared_memory sharedMemory(bi::open_only, SHARED_MEMORY_NAME);
  auto messageQueue =
      sharedMemory.find<MessageQueue>(SHARED_MESSAGE_QUEUE_NAME).first;

  // Setup processing
  Dyld::Context dCtx(args.cachePath);
  Provider::Accelerator<P> accelerator;

  // tell server about first image
  if (auto i = args.clientSpec.start; i < args.clientSpec.end) {
    auto nextImageName =
        getImageName(dCtx, dCtx.images[args.clientSpec.start]).second;
    sendMessage(messageQueue,
                {args.clientSpec.clientID, "", "", nextImageName});
  }

  for (auto i = args.clientSpec.start; i < args.clientSpec.end;
       i += args.clientSpec.skip) {
    auto imageInfo = dCtx.images[i];
    auto [imagePath, imageName] = getImageName(dCtx, imageInfo);
    auto loggerStream = processImage<A>(args, dCtx, accelerator, imageInfo,
                                        imagePath, imageName);

    // Peek ahead
    std::string nextImageName = "";
    if (auto nextI = i + args.clientSpec.skip; nextI < args.clientSpec.end) {
      nextImageName = getImageName(dCtx, dCtx.images[nextI]).second;
    }

    // Send logs
    sendMessage(messageQueue, {args.clientSpec.clientID, imageName,
                               loggerStream.str(), nextImageName});
  }

  return 0;
}
#pragma endregion Client

int main(int argc, char const *argv[]) {
  auto args = parseArgs(argc, argv);
  if (args.clientSpec.inClientMode) {
    try {
      switch (args.clientSpec.arch) {
      case ProgramArguments::ClientSpecification::Arch::x86_64:
        return client<Utils::Arch::x86_64>(args);
      case ProgramArguments::ClientSpecification::Arch::arm:
        return client<Utils::Arch::arm>(args);
      case ProgramArguments::ClientSpecification::Arch::arm64:
        return client<Utils::Arch::arm64>(args);
      case ProgramArguments::ClientSpecification::Arch::arm64_32:
        return client<Utils::Arch::arm64_32>(args);
      default:
        std::cerr << fmt::format("\nUnknown architecture type {}.",
                                 static_cast<int>(args.clientSpec.arch))
                  << std::endl;
        return 1;
      }
    } catch (const std::exception &e) {
      std::cerr << fmt::format("\nClient {}: critical error: {}",
                               args.clientSpec.clientID, e.what())
                << std::endl;
      return 1;
    }
  } else {
    // Check arguments
    if (!args.disableOutput && !args.outputDir && !args.onlyValidate) {
      std::cerr << "Output directory is required for extraction" << std::endl;
      return 1;
    }

    try {
      Dyld::Context dCtx(args.cachePath);

      // use dyld's magic to select arch
      int retCode;
      if (strcmp(dCtx.header->magic, "dyld_v1  x86_64") == 0)
        retCode = server<Utils::Arch::x86_64>(args, dCtx);
      else if (strcmp(dCtx.header->magic, "dyld_v1 x86_64h") == 0)
        retCode = server<Utils::Arch::x86_64>(args, dCtx);
      else if (strcmp(dCtx.header->magic, "dyld_v1   armv7") == 0)
        retCode = server<Utils::Arch::arm>(args, dCtx);
      else if (strncmp(dCtx.header->magic, "dyld_v1  armv7", 14) == 0)
        retCode = server<Utils::Arch::arm>(args, dCtx);
      else if (strcmp(dCtx.header->magic, "dyld_v1   arm64") == 0)
        retCode = server<Utils::Arch::arm64>(args, dCtx);
      else if (strcmp(dCtx.header->magic, "dyld_v1  arm64e") == 0)
        retCode = server<Utils::Arch::arm64>(args, dCtx);
      else if (strcmp(dCtx.header->magic, "dyld_v1arm64_32") == 0)
        retCode = server<Utils::Arch::arm64_32>(args, dCtx);
      else if (strcmp(dCtx.header->magic, "dyld_v1    i386") == 0 ||
               strcmp(dCtx.header->magic, "dyld_v1   armv5") == 0 ||
               strcmp(dCtx.header->magic, "dyld_v1   armv6") == 0) {
        std::cerr << "Unsupported architecture type." << std::endl;
        retCode = 1;
      } else {
        std::cerr << "Unrecognized dyld shared cache magic." << std::endl;
        retCode = 1;
      }

      return retCode;
    } catch (const std::exception &e) {
      std::cerr << fmt::format("Critical error: {}", e.what()) << std::endl;
      return 1;
    }
  }
}

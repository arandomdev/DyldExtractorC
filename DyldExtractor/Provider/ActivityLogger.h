#ifndef __PROVIDER_ACTIVITYLOGGER__
#define __PROVIDER_ACTIVITYLOGGER__

#include <chrono>
#include <iostream>
#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

namespace DyldExtractor::Provider {

class ActivityLogger {
  /// @brief A wrapper for a streambuf that allows an activity indicator.
  ///
  /// Essentially does new line, moves line up, and insert line, before
  /// every line.
  class StreamBuffer : public std::streambuf {
  public:
    StreamBuffer(std::streambuf *buffer);

  private:
    std::streambuf *buffer;

    /// Thanks to alkis-pap from github.com/p-ranav/indicators/issues/107
    /// Move up, insert line
    const std::string prefix = "\n\033[A\033[1L";
    bool needPrefix;

    int sync();
    int overflow(int c);
  };

public:
  /// @brief Create a logger with an optional activity indicator.
  /// @param name The name of the logger.
  /// @param output The output stream.
  /// @param enableActivity Enable or disable the activity indicator.
  ActivityLogger(std::string name, std::ostream &output, bool enableActivity);

  ActivityLogger(const ActivityLogger &) = delete;
  ActivityLogger(const ActivityLogger &&) = delete;
  ActivityLogger &operator=(ActivityLogger &) = delete;
  ActivityLogger &operator=(ActivityLogger &&) = delete;

  /// Update the activity indicator.
  ///
  /// @param module The name of the module.
  /// @param message The message.
  void update(std::optional<std::string> moduleName = std::nullopt,
              std::optional<std::string> message = std::nullopt,
              bool fullUpdate = false);

  /// @brief Stop the activity indicator
  void stopActivity();

  /// @brief Get the spdlog logger
  std::shared_ptr<spdlog::logger> getLogger();

  /// @brief Get the logger stream that won't interfere with
  /// the activity indicator.
  std::ostream &getLoggerStream();

private:
  std::shared_ptr<spdlog::logger> logger;
  std::ostream &activityStream;
  std::ostream loggerStream;
  StreamBuffer streamBuffer;

  bool enableActivity;
  std::string currentModule = "---";
  std::string currentMessage = "---";
  int currentActivityState = 0;
  const std::vector<std::string> activityStates = {"|", "/", "-", "\\"};
  std::chrono::time_point<std::chrono::high_resolution_clock>
      lastActivityUpdate;

  std::chrono::seconds lastElapsedTime;
  const std::chrono::time_point<std::chrono::high_resolution_clock> startTime;

  std::string _formatTime(std::chrono::seconds seconds);
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_ACTIVITYLOGGER__
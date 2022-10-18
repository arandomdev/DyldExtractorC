#include "Activity.h"

#include <exception>

using namespace DyldExtractor;
using namespace Logger;

StreamBuffer::StreamBuffer(std::streambuf *buffer) : buffer(buffer) {}

int StreamBuffer::sync() { return buffer->pubsync(); }

int StreamBuffer::overflow(int c) {
  if (c != std::char_traits<char>::eof()) {
    if (needPrefix &&
        prefix.size() != buffer->sputn(prefix.c_str(), prefix.size())) {
      return std::char_traits<char>::eof();
    }
    needPrefix = (c == '\n');
  }

  return buffer->sputc(c);
}

Activity::Activity(std::string name, std::ostream &output, bool enableActivity)
    : activityStream(output), loggerStream(&streamBuffer),
      streamBuffer(output.rdbuf()), enableActivity(enableActivity),
      lastActivityUpdate(std::chrono::high_resolution_clock::now()),
      lastElapsedTime(0), startTime(std::chrono::high_resolution_clock::now()) {
  std::shared_ptr<spdlog::sinks::ostream_sink_st> streamSink;
  if (enableActivity) {
    // Create a logger with the special buffer
    streamSink = std::make_shared<spdlog::sinks::ostream_sink_st>(loggerStream);

    // preload activity
    update(currentModule, currentMessage, true);
  } else {
    streamSink = std::make_shared<spdlog::sinks::ostream_sink_st>(output);
  }

  logger = std::make_shared<spdlog::logger>(name, streamSink);
}

void Activity::update(std::optional<std::string> moduleName,
                      std::optional<std::string> message, bool fullUpdate) {
  if (!enableActivity) {
    return;
  }

  // Format, [(/) Elapsed Time] Module - Text
  unsigned int updateLevel = fullUpdate ? INT_MAX : 0;

  // Spinner
  auto currentTime = std::chrono::high_resolution_clock::now();
  if (std::chrono::duration_cast<std::chrono::milliseconds>(currentTime -
                                                            lastActivityUpdate)
          .count() > 150) {
    lastActivityUpdate = currentTime;
    currentActivityState = (currentActivityState + 1) % activityStates.size();
    updateLevel |= 0b1;
  }

  // elapsed time
  auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::high_resolution_clock::now() - startTime);
  if (elapsedTime != lastElapsedTime) {
    lastElapsedTime = elapsedTime;
    updateLevel |= 0b10;
  }

  // text
  if (moduleName) {
    currentModule = moduleName.value();
    updateLevel |= 0b100;
  }
  if (message) {
    currentMessage = message.value();
    updateLevel |= 0b100;
  }

  // Update
  std::string output;
  if (updateLevel >= 0b100) {
    output = fmt::format(
        "\033[2K[({}) {}] {} - {}", activityStates[currentActivityState],
        _formatTime(elapsedTime), currentModule, currentMessage);
  } else if (updateLevel >= 0b10) {
    output = fmt::format("[({}) {}", activityStates[currentActivityState],
                         _formatTime(elapsedTime));
  } else if (updateLevel >= 0b1) {
    output = fmt::format("[({}", activityStates[currentActivityState]);
  }

  if (output.length()) {
    activityStream << output + "\r" << std::flush;
  }
}

void Activity::stopActivity() {
  if (enableActivity) {
    enableActivity = false;
    activityStream << "\n";
  }
}

std::ostream &Activity::getLoggerStream() { return loggerStream; }

std::string Activity::_formatTime(std::chrono::seconds seconds) {
  auto minutes = std::chrono::duration_cast<std::chrono::minutes>(seconds);
  seconds -= minutes;

  return fmt::format("{:02d}:{:02d}", minutes.count(), seconds.count());
}
#include "ActivityLogger.h"

#include <exception>

_LoggerStreamBuffer::_LoggerStreamBuffer(std::streambuf *buffer)
    : _buffer(buffer) {}

int _LoggerStreamBuffer::sync() { return _buffer->pubsync(); }

int _LoggerStreamBuffer::overflow(int c) {
    if (c != std::char_traits<char>::eof()) {
        if (_needPrefix &&
            _prefix.size() != _buffer->sputn(_prefix.c_str(), _prefix.size())) {
            return std::char_traits<char>::eof();
        }
        _needPrefix = (c == '\n');
    }

    return _buffer->sputc(c);
}

ActivityLogger::ActivityLogger(std::string name, std::ostream &output,
                               bool enableActivity)
    : _activityStream(output), _loggerStream(&_streamBuffer),
      _streamBuffer(output.rdbuf()), _enableActivity(enableActivity),
      _lastActivityUpdate(std::chrono::high_resolution_clock::now()),
      _lastElapsedTime(0),
      _startTime(std::chrono::high_resolution_clock::now()) {
    std::shared_ptr<spdlog::sinks::ostream_sink_st> streamSink;
    if (enableActivity) {
        // Create a logger with the special buffer
        streamSink =
            std::make_shared<spdlog::sinks::ostream_sink_st>(_loggerStream);

        // preload activity
        update(_currentModule, _currentMessage, true);
    } else {
        streamSink = std::make_shared<spdlog::sinks::ostream_sink_st>(output);
    }

    logger = std::make_shared<spdlog::logger>(name, streamSink);
}

void ActivityLogger::update(std::optional<std::string> moduleName,
                            std::optional<std::string> message,
                            bool fullUpdate) {
    if (!_enableActivity) {
        return;
    }

    // Format, [(/) Elapsed Time] Module - Text
    unsigned int updateLevel = fullUpdate ? INT_MAX : 0;

    // Spinner
    auto currentTime = std::chrono::high_resolution_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(
            currentTime - _lastActivityUpdate)
            .count() > 150) {
        _lastActivityUpdate = currentTime;
        _currentActivityState =
            (_currentActivityState + 1) % _activityStates.size();
        updateLevel |= 0b1;
    }

    // elapsed time
    auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::high_resolution_clock::now() - _startTime);
    if (elapsedTime != _lastElapsedTime) {
        _lastElapsedTime = elapsedTime;
        updateLevel |= 0b10;
    }

    // text
    if (moduleName) {
        _currentModule = moduleName.value();
        updateLevel |= 0b100;
    }
    if (message) {
        _currentMessage = message.value();
        updateLevel |= 0b100;
    }

    // Update
    std::string output;
    if (updateLevel >= 0b100) {
        output = fmt::format(
            "\033[2K[({}) {}] {} - {}", _activityStates[_currentActivityState],
            _formatTime(elapsedTime), _currentModule, _currentMessage);
    } else if (updateLevel >= 0b10) {
        output = fmt::format("[({}) {}", _activityStates[_currentActivityState],
                             _formatTime(elapsedTime));
    } else if (updateLevel >= 0b1) {
        output = fmt::format("[({}", _activityStates[_currentActivityState]);
    }

    if (output.length()) {
        _activityStream << output + "\r" << std::flush;
    }
}

void ActivityLogger::stopActivity() {
    if (_enableActivity) {
        _enableActivity = false;
        _activityStream << "\n";
    }
}

std::ostream &ActivityLogger::loggerStream() { return _loggerStream; }

std::string ActivityLogger::_formatTime(std::chrono::seconds seconds) {
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(seconds);
    seconds -= minutes;

    return fmt::format("{:02d}:{:02d}", minutes.count(), seconds.count());
}
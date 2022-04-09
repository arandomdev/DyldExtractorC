#include "ActivityLogger.h"

#include <exception>
#include <fmt/format.h>

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
    std::shared_ptr<spdlog::sinks::ostream_sink_mt> streamSink;
    if (enableActivity) {
        // Create a logger with the special buffer
        streamSink =
            std::make_shared<spdlog::sinks::ostream_sink_mt>(_loggerStream);

        // preload activity
        _updateActivity(true);
    } else {
        streamSink = std::make_shared<spdlog::sinks::ostream_sink_mt>(output);
    }

    logger = std::make_shared<spdlog::logger>(name, streamSink);
}

void ActivityLogger::update(std::optional<std::string> moduleName,
                            std::optional<std::string> message) {
    if (!_enableActivity) {
        return;
    }

    bool textChanged = false;
    if (moduleName) {
        _currentModule = moduleName.value();
        textChanged = true;
    }
    if (message) {
        _currentMessage = message.value();
        textChanged = true;
    }

    if (textChanged) {
        _updateActivity(true);
        return;
    }

    // only update the activity occasionally
    auto currentTime = std::chrono::high_resolution_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(
            currentTime - _lastActivityUpdate)
            .count() > 150) {
        _lastActivityUpdate = currentTime;
        _updateActivity(false);
    }
}

void ActivityLogger::stopActivity() {
    _enableActivity = false;
    _activityStream << "\n";
}

void ActivityLogger::_updateActivity(bool fullRefesh) {
    // Format, [(/) Elapsed Time] Module - Text
    std::string output;
    auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::high_resolution_clock::now() - _startTime);

    if (fullRefesh) {
        // just update the text
        output = fmt::format("\033[2K[({}) {}] {} - {}\r",
                             _activityStates[_currentActivityState],
                             _formatTime(elapsedTime), _currentModule,
                             _currentMessage);
        _lastElapsedTime = elapsedTime;
        _activityStream << output;
        return;
    }

    // update the spinner
    _currentActivityState =
        (_currentActivityState + 1) % _activityStates.size();
    output = fmt::format("[({}", _activityStates[_currentActivityState]);

    // update the elapsed time if needed
    if (elapsedTime != _lastElapsedTime) {
        output += ") " + _formatTime(elapsedTime);
        _lastElapsedTime = elapsedTime;
    }

    _activityStream << output + "\r" << std::flush;
}

std::string ActivityLogger::_formatTime(std::chrono::seconds seconds) {
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(seconds);
    seconds -= minutes;

    return fmt::format("{:02d}:{:02d}", minutes.count(), seconds.count());
}
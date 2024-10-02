#pragma once

enum class LogLevel { ERROR, WARNING, INFO, DEBUG };

struct ILog {
    virtual void log(LogLevel log_level, const char* format, ...) = 0;
};

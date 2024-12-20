#pragma once

struct ILog {
    virtual void Log(const char* format, ...) = 0;
};

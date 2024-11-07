#pragma once
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>

enum LogLevel {
    _INFO,
    _WARNING,
    _ERROR,
    _DEBUG,
    _FATAL,
};

class Debug {
public:
    template<typename... Args>
    static void log(LogLevel level, Args... args) {
        std::string levelStr;

        switch (level) {
        case _DEBUG: levelStr = "DEBUG"; break;
        case _INFO: levelStr = "INFO"; break;
        case _WARNING: levelStr = "WARNING"; break;
        case _ERROR: levelStr = "ERROR"; break;
        }

        std::string colorCode = getColorCode(level);
        std::string resetCode = "\033[0m";
        std::string message = concatMessages(args...);

        std::cout << colorCode << "[" << getCurrentTime() << "] [" << levelStr << "] " << message << resetCode << std::endl;
    }
private:
    static std::string getCurrentTime() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm;

        localtime_s(&now_tm, &now_time);

        std::ostringstream oss;
        oss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    static std::string getColorCode(LogLevel level) {
        switch (level) {
        case _DEBUG: return "\033[0;36m";
        case _INFO: return "\033[0;32m";
        case _WARNING: return "\033[0;33m";
        case _ERROR: return "\033[0;31m";
        default: return "\033[0m";
        }
    }

    template<typename... Args>
    static std::string concatMessages(Args... args) {
        std::ostringstream oss;
        (oss << ... << args);
        return oss.str();
    }
};

static Debug debug = Debug();
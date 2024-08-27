#ifndef __ACCESS_LOG_H
#define __ACCESS_LOG_H

#include "Connection.h"
#include "mem.h"

#include <string>
#include <fstream>
#include <memory>
#include <vector>
#include <ctime>
#include <cstdint>

class Log {
public:
    struct LogFile {
        std::string filename;
        FILE *file;
        std::string fmt;
    };
    static bool AddLogFile(std::string &logpath, std::string &fmt);
    static void CloseLogFiles(std::vector<Log::LogFile> &logFiles);
    static std::vector<Log::LogFile> LogFiles;
};

#endif
